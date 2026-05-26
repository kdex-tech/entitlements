use std::collections::HashMap;

/// Represents a security scheme (e.g., "bearer", "oauth2").
pub type SecurityScheme = String;

/// A map of entitlements grouped by security scheme.
pub type Entitlements = HashMap<SecurityScheme, Vec<String>>;

/// A single requirement set (map of schemes to required patterns).
pub type RequirementSet = HashMap<SecurityScheme, Vec<String>>;

/// A list of alternative requirement sets (OR'd).
pub type Requirements = Vec<RequirementSet>;

/// A parsed representation of an entitlement or requirement pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// Long form: <resource>:<resourceName>:<verb>
    Structured {
        resource: String,
        name: String,
        verb: String,
    },
    /// Opaque form: <string>
    Opaque(String),
}

impl Pattern {
    /// Parses a pattern string into a Pattern enum.
    pub fn parse(s: &str) -> Self {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.len() {
            3 => Self::Structured {
                resource: parts[0].to_string(),
                name: parts[1].to_string(),
                verb: parts[2].to_string(),
            },
            2 => Self::Structured {
                resource: parts[0].to_string(),
                name: "*".to_string(),
                verb: parts[1].to_string(),
            },
            _ => Self::Opaque(s.to_string()),
        }
    }

    /// Checks if this pattern (as an entitlement) satisfies the required pattern.
    pub fn satisfies(&self, required: &Pattern) -> bool {
        match (self, required) {
            (Self::Opaque(e), Self::Opaque(r)) => e == r,
            (
                Self::Structured {
                    resource: er,
                    name: en,
                    verb: ev,
                },
                Self::Structured {
                    resource: rr,
                    name: rn,
                    verb: rv,
                },
            ) => {
                // Resource types must match
                if er != rr {
                    return false;
                }

                // Verb must match exactly or entitlement verb is "all"
                if ev != rv && ev != "all" {
                    return false;
                }

                // Name must match exactly, or either is a wildcard
                if en != rn && en != "*" && !en.is_empty() && rn != "*" && !rn.is_empty() {
                    return false;
                }

                true
            }
            // Mixed forms only match exactly if they are identical strings (unlikely given parse logic)
            _ => false,
        }
    }
}

/// The main entitlements checker.
pub struct EntitlementsChecker {
    anonymous_entitlements: Vec<Pattern>,
    base_entitlements: Vec<Pattern>,
    default_scheme: String,
}

impl EntitlementsChecker {
    pub fn new(anonymous_entitlements: Vec<String>, default_scheme: String) -> Self {
        let parsed_anon = anonymous_entitlements.iter().map(|s| Pattern::parse(s)).collect();
        Self {
            anonymous_entitlements: parsed_anon,
            base_entitlements: Vec::new(),
            default_scheme,
        }
    }

    /// Sets the base entitlements: patterns that apply to every caller
    /// (authenticated or anonymous) under the default scheme. Unlike
    /// `anonymous_entitlements` (which apply only when the caller's
    /// entitlements map is empty), base entitlements form a floor of grants
    /// that every request receives.
    ///
    /// Replaces any previously set base entitlements. Consuming-self
    /// builder; intended for use during checker construction.
    pub fn with_base_entitlements(mut self, patterns: Vec<String>) -> Self {
        self.base_entitlements = patterns.iter().map(|s| Pattern::parse(s)).collect();
        self
    }

    /// Verifies if the user's entitlements satisfy any of the requirements.
    pub fn verify(&self, user_entitlements: &Entitlements, requirements: &Requirements) -> bool {
        if requirements.is_empty() {
            return true;
        }

        let parsed: HashMap<String, Vec<Pattern>> = user_entitlements
            .iter()
            .map(|(scheme, list)| (scheme.clone(), list.iter().map(|s| Pattern::parse(s)).collect()))
            .collect();

        let is_anonymous = parsed.is_empty() || parsed.values().all(|v| v.is_empty());

        for req_set in requirements {
            if self.verify_set(&parsed, req_set, is_anonymous) {
                return true;
            }
        }

        false
    }

    fn verify_set(
        &self,
        user_patterns: &HashMap<String, Vec<Pattern>>,
        req_set: &RequirementSet,
        is_anonymous: bool,
    ) -> bool {
        for (scheme, required_patterns) in req_set {
            let user_list_present = user_patterns.contains_key(scheme);
            let has_fallback = scheme == &self.default_scheme
                && (!self.base_entitlements.is_empty()
                    || (is_anonymous && !self.anonymous_entitlements.is_empty()));
            if !user_list_present && !has_fallback {
                return false;
            }

            let empty: Vec<Pattern> = Vec::new();
            let user_list = user_patterns.get(scheme).unwrap_or(&empty);

            for req_str in required_patterns {
                let req_p = Pattern::parse(req_str);
                let satisfied_by_user = user_list.iter().any(|p| p.satisfies(&req_p));
                let satisfied_by_base = scheme == &self.default_scheme
                    && self.base_entitlements.iter().any(|p| p.satisfies(&req_p));
                let satisfied_by_anon = scheme == &self.default_scheme
                    && is_anonymous
                    && self.anonymous_entitlements.iter().any(|p| p.satisfies(&req_p));
                if !satisfied_by_user && !satisfied_by_base && !satisfied_by_anon {
                    return false;
                }
            }
        }
        true
    }

    /// Verifies access for a specific resource instance.
    pub fn verify_resource(
        &self,
        user_entitlements: &Entitlements,
        resource: &str,
        name: &str,
        verb: &str,
        additional_requirements: &Requirements,
    ) -> bool {
        let identity_req = format!("{}:{}:{}", resource, name, verb);

        if additional_requirements.is_empty() {
            let mut set = RequirementSet::new();
            set.insert(self.default_scheme.clone(), vec![identity_req]);
            return self.verify(user_entitlements, &vec![set]);
        }

        let mut combined_requirements = Vec::new();
        for set in additional_requirements {
            let mut new_set = set.clone();
            new_set
                .entry(self.default_scheme.clone())
                .or_default()
                .push(identity_req.clone());
            combined_requirements.push(new_set);
        }

        self.verify(user_entitlements, &combined_requirements)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_parse() {
        assert_eq!(
            Pattern::parse("pages:/foo:read"),
            Pattern::Structured {
                resource: "pages".to_string(),
                name: "/foo".to_string(),
                verb: "read".to_string()
            }
        );
        assert_eq!(
            Pattern::parse("pages:read"),
            Pattern::Structured {
                resource: "pages".to_string(),
                name: "*".to_string(),
                verb: "read".to_string()
            }
        );
        assert_eq!(Pattern::parse("admin"), Pattern::Opaque("admin".to_string()));
    }

    #[test]
    fn test_verify() {
        let checker = EntitlementsChecker::new(vec!["anonymous:read".to_string()], "bearer".to_string());
        
        let mut entitlements = Entitlements::new();
        entitlements.insert("bearer".to_string(), vec!["pages:foo:read".to_string()]);
        
        // Simple match
        let mut req_set = RequirementSet::new();
        req_set.insert("bearer".to_string(), vec!["pages:foo:read".to_string()]);
        let requirements = vec![req_set];
        assert!(checker.verify(&entitlements, &requirements));
        
        // Wildcard match
        let mut req_set = RequirementSet::new();
        req_set.insert("bearer".to_string(), vec!["pages:*:read".to_string()]);
        let requirements = vec![req_set];
        assert!(checker.verify(&entitlements, &requirements));

        // Authed caller does NOT get the anonymous bag (regression for issue #3)
        let mut req_set = RequirementSet::new();
        req_set.insert("bearer".to_string(), vec!["anonymous:*:read".to_string()]);
        let requirements = vec![req_set];
        assert!(!checker.verify(&entitlements, &requirements));

        // Anonymous caller DOES get the anonymous bag
        let empty_entitlements = Entitlements::new();
        let mut req_set = RequirementSet::new();
        req_set.insert("bearer".to_string(), vec!["anonymous:*:read".to_string()]);
        let requirements = vec![req_set];
        assert!(checker.verify(&empty_entitlements, &requirements));

        // Failing match
        let mut req_set = RequirementSet::new();
        req_set.insert("bearer".to_string(), vec!["pages:foo:write".to_string()]);
        let requirements = vec![req_set];
        assert!(!checker.verify(&entitlements, &requirements));

        // OR match
        let mut req_set1 = RequirementSet::new();
        req_set1.insert("bearer".to_string(), vec!["pages:foo:write".to_string()]);
        let mut req_set2 = RequirementSet::new();
        req_set2.insert("bearer".to_string(), vec!["pages:foo:read".to_string()]);
        let requirements = vec![req_set1, req_set2];
        assert!(checker.verify(&entitlements, &requirements));
    }

    #[test]
    fn test_verify_resource() {
        let checker = EntitlementsChecker::new(vec![], "bearer".to_string());
        let mut entitlements = Entitlements::new();
        entitlements.insert("bearer".to_string(), vec!["pages:foo:read".to_string(), "admin".to_string()]);

        // Identity check
        assert!(checker.verify_resource(&entitlements, "pages", "foo", "read", &vec![]));
        assert!(!checker.verify_resource(&entitlements, "pages", "bar", "read", &vec![]));

        // Identity + additional requirements
        let mut req_set = RequirementSet::new();
        req_set.insert("bearer".to_string(), vec!["admin".to_string()]);
        let additional = vec![req_set];
        assert!(checker.verify_resource(&entitlements, "pages", "foo", "read", &additional));

        let mut req_set = RequirementSet::new();
        req_set.insert("bearer".to_string(), vec!["superadmin".to_string()]);
        let additional = vec![req_set];
        assert!(!checker.verify_resource(&entitlements, "pages", "foo", "read", &additional));
    }

    #[test]
    fn test_anonymous_vs_base() {
        let checker = EntitlementsChecker::new(
            vec!["anon:read".to_string()],
            "bearer".to_string(),
        )
        .with_base_entitlements(vec!["base:read".to_string()]);

        let mut authed = Entitlements::new();
        authed.insert("bearer".to_string(), vec!["pages:foo:read".to_string()]);
        let anonymous = Entitlements::new();

        let need_anon = vec![{
            let mut s = RequirementSet::new();
            s.insert("bearer".to_string(), vec!["anon:read".to_string()]);
            s
        }];
        let need_base = vec![{
            let mut s = RequirementSet::new();
            s.insert("bearer".to_string(), vec!["base:read".to_string()]);
            s
        }];

        // Authed caller: base yes, anon no
        assert!(checker.verify(&authed, &need_base));
        assert!(!checker.verify(&authed, &need_anon));

        // Anonymous caller: both
        assert!(checker.verify(&anonymous, &need_base));
        assert!(checker.verify(&anonymous, &need_anon));

        // Authed caller with only an empty scheme list is still anonymous
        let mut empty_list = Entitlements::new();
        empty_list.insert("bearer".to_string(), vec![]);
        assert!(checker.verify(&empty_list, &need_anon));
    }

    #[test]
    fn test_anonymous_vs_base_via_verify_resource() {
        // Authed caller satisfies identity via base
        let base_checker = EntitlementsChecker::new(vec![], "bearer".to_string())
            .with_base_entitlements(vec!["pages:/foo:read".to_string()]);
        let mut authed = Entitlements::new();
        authed.insert("bearer".to_string(), vec!["other:read".to_string()]);
        assert!(base_checker.verify_resource(&authed, "pages", "/foo", "read", &vec![]));

        // Anonymous caller satisfies identity via base
        let anonymous = Entitlements::new();
        assert!(base_checker.verify_resource(&anonymous, "pages", "/foo", "read", &vec![]));

        // Authed caller does NOT satisfy identity via anonymous bag
        let anon_checker = EntitlementsChecker::new(
            vec!["pages:/foo:read".to_string()],
            "bearer".to_string(),
        );
        assert!(!anon_checker.verify_resource(&authed, "pages", "/foo", "read", &vec![]));

        // Anonymous caller DOES satisfy identity via anonymous bag
        assert!(anon_checker.verify_resource(&anonymous, "pages", "/foo", "read", &vec![]));
    }

    #[test]
    fn test_with_base_entitlements_replaces() {
        let checker = EntitlementsChecker::new(vec![], "bearer".to_string())
            .with_base_entitlements(vec!["first:read".to_string()])
            .with_base_entitlements(vec!["second:read".to_string()]);

        let mut authed = Entitlements::new();
        authed.insert("bearer".to_string(), vec!["pages:foo:read".to_string()]);

        let need_first = vec![{
            let mut s = RequirementSet::new();
            s.insert("bearer".to_string(), vec!["first:read".to_string()]);
            s
        }];
        let need_second = vec![{
            let mut s = RequirementSet::new();
            s.insert("bearer".to_string(), vec!["second:read".to_string()]);
            s
        }];

        assert!(!checker.verify(&authed, &need_first));
        assert!(checker.verify(&authed, &need_second));
    }
}
