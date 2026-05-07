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
    anonymous_entitlements: Vec<String>,
    default_scheme: String,
}

impl EntitlementsChecker {
    pub fn new(anonymous_entitlements: Vec<String>, default_scheme: String) -> Self {
        Self {
            anonymous_entitlements,
            default_scheme,
        }
    }

    /// Verifies if the user's entitlements satisfy any of the requirements.
    pub fn verify(&self, user_entitlements: &Entitlements, requirements: &Requirements) -> bool {
        if requirements.is_empty() {
            return true;
        }

        // Merge user entitlements with anonymous ones
        let mut merged = user_entitlements.clone();
        if !self.anonymous_entitlements.is_empty() {
            let entry = merged
                .entry(self.default_scheme.clone())
                .or_default();
            for anon in &self.anonymous_entitlements {
                if !entry.contains(anon) {
                    entry.push(anon.clone());
                }
            }
        }

        // Pre-parse user entitlements for performance
        let parsed_entitlements: HashMap<String, Vec<Pattern>> = merged
            .iter()
            .map(|(scheme, list)| {
                (
                    scheme.clone(),
                    list.iter().map(|s| Pattern::parse(s)).collect(),
                )
            })
            .collect();

        // Check each alternative requirement set (OR)
        for req_set in requirements {
            if self.verify_set(&parsed_entitlements, req_set) {
                return true;
            }
        }

        false
    }

    /// Verifies if a single requirement set is satisfied (AND logic).
    fn verify_set(
        &self,
        user_patterns: &HashMap<String, Vec<Pattern>>,
        req_set: &RequirementSet,
    ) -> bool {
        for (scheme, required_patterns) in req_set {
            let user_list = match user_patterns.get(scheme) {
                Some(list) => list,
                None => return false, // Scheme not present in user entitlements
            };

            for req_str in required_patterns {
                let req_p = Pattern::parse(req_str);
                let satisfied = user_list.iter().any(|user_p| user_p.satisfies(&req_p));
                if !satisfied {
                    return false; // All requirements for a scheme must be met
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
        
        // If no additional requirements, just check the identity
        if additional_requirements.is_empty() {
            let mut set = RequirementSet::new();
            set.insert(self.default_scheme.clone(), vec![identity_req]);
            return self.verify(user_entitlements, &vec![set]);
        }

        // Otherwise, the identity requirement must be satisfied AND one of the alternative sets
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

        // Anonymous match
        let mut req_set = RequirementSet::new();
        req_set.insert("bearer".to_string(), vec!["anonymous:*:read".to_string()]);
        let requirements = vec![req_set];
        assert!(checker.verify(&entitlements, &requirements));

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
}
