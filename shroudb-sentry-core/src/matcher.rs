use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Matches against the principal in an evaluation request.
///
/// Empty fields are wildcards (match anything).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrincipalMatcher {
    /// Roles to match against. Any role matching grants a hit (OR logic).
    /// Empty means match any principal regardless of role.
    #[serde(default)]
    pub roles: Vec<String>,

    /// Claims to match against. All claims must match (AND logic).
    /// Empty means no claim requirements.
    #[serde(default)]
    pub claims: HashMap<String, String>,
}

/// Matches against the resource in an evaluation request.
///
/// Empty fields are wildcards.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceMatcher {
    /// Resource type to match (exact). Empty means match any type.
    #[serde(rename = "type", default)]
    pub resource_type: String,

    /// Attributes to match against. All must match (AND logic).
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

/// Matches against the action in an evaluation request.
///
/// Empty means match any action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionMatcher {
    /// Action names to match. Any match grants a hit (OR, case-insensitive).
    /// Empty means match any action.
    #[serde(default)]
    pub names: Vec<String>,
}

/// Optional conditions that must hold for a policy to apply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conditions {
    /// Time window during which the policy applies.
    #[serde(default)]
    pub time_window: Option<TimeWindow>,
}

/// A UTC time window constraint.
///
/// Both `after` and `before` are optional. Supports overnight wrap
/// (e.g., after=22:00 before=06:00 means 22:00 → 06:00 next day).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start time (inclusive), "HH:MM" in UTC.
    pub after: Option<String>,
    /// End time (exclusive), "HH:MM" in UTC.
    pub before: Option<String>,
}

impl PrincipalMatcher {
    /// Check if this matcher matches the given principal.
    pub fn matches(&self, roles: &[String], claims: &HashMap<String, String>) -> bool {
        // Check roles: if we have roles, at least one must match (OR)
        if !self.roles.is_empty()
            && !self
                .roles
                .iter()
                .any(|r| roles.iter().any(|pr| pr.eq_ignore_ascii_case(r)))
        {
            return false;
        }

        // Check claims: all must match (AND)
        for (key, value) in &self.claims {
            match claims.get(key) {
                Some(v) if v == value => {}
                _ => return false,
            }
        }

        true
    }
}

impl ResourceMatcher {
    /// Check if this matcher matches the given resource.
    pub fn matches(&self, resource_type: &str, attributes: &HashMap<String, String>) -> bool {
        // Check type: if specified, must match exactly
        if !self.resource_type.is_empty() && !self.resource_type.eq_ignore_ascii_case(resource_type)
        {
            return false;
        }

        // Check attributes: all must match (AND)
        for (key, value) in &self.attributes {
            match attributes.get(key) {
                Some(v) if v == value => {}
                _ => return false,
            }
        }

        true
    }
}

impl ActionMatcher {
    /// Check if this matcher matches the given action.
    pub fn matches(&self, action: &str) -> bool {
        if self.names.is_empty() {
            return true;
        }
        self.names.iter().any(|n| n.eq_ignore_ascii_case(action))
    }
}

impl TimeWindow {
    /// Check if the given hour:minute (UTC) falls within this window.
    pub fn contains(&self, hour: u32, minute: u32) -> bool {
        let now = hour * 60 + minute;

        let after_mins = self.after.as_ref().and_then(|s| parse_hhmm(s));
        let before_mins = self.before.as_ref().and_then(|s| parse_hhmm(s));

        match (after_mins, before_mins) {
            (Some(a), Some(b)) if a <= b => now >= a && now < b,
            (Some(a), Some(b)) => now >= a || now < b, // overnight wrap
            (Some(a), None) => now >= a,
            (None, Some(b)) => now < b,
            (None, None) => true,
        }
    }
}

impl Conditions {
    /// Check if all conditions are satisfied at the given UTC hour:minute.
    pub fn satisfied(&self, hour: u32, minute: u32) -> bool {
        if let Some(tw) = &self.time_window {
            return tw.contains(hour, minute);
        }
        true
    }
}

fn parse_hhmm(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let h: u32 = parts[0].parse().ok()?;
    let m: u32 = parts[1].parse().ok()?;
    if h >= 24 || m >= 60 {
        return None;
    }
    Some(h * 60 + m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_wildcard_matches_anything() {
        let m = PrincipalMatcher::default();
        assert!(m.matches(&[], &HashMap::new()));
        assert!(m.matches(&["admin".into()], &HashMap::new()));
    }

    #[test]
    fn principal_role_or_match() {
        let m = PrincipalMatcher {
            roles: vec!["editor".into(), "admin".into()],
            claims: HashMap::new(),
        };
        assert!(m.matches(&["editor".into()], &HashMap::new()));
        assert!(m.matches(&["admin".into()], &HashMap::new()));
        assert!(!m.matches(&["viewer".into()], &HashMap::new()));
    }

    #[test]
    fn principal_claims_and_match() {
        let m = PrincipalMatcher {
            roles: Vec::new(),
            claims: HashMap::from([
                ("dept".into(), "eng".into()),
                ("level".into(), "senior".into()),
            ]),
        };
        let claims = HashMap::from([
            ("dept".into(), "eng".into()),
            ("level".into(), "senior".into()),
            ("extra".into(), "ignored".into()),
        ]);
        assert!(m.matches(&[], &claims));

        let partial = HashMap::from([("dept".into(), "eng".into())]);
        assert!(!m.matches(&[], &partial));
    }

    #[test]
    fn resource_wildcard() {
        let m = ResourceMatcher::default();
        assert!(m.matches("document", &HashMap::new()));
    }

    #[test]
    fn resource_type_match() {
        let m = ResourceMatcher {
            resource_type: "document".into(),
            attributes: HashMap::new(),
        };
        assert!(m.matches("document", &HashMap::new()));
        assert!(m.matches("Document", &HashMap::new()));
        assert!(!m.matches("endpoint", &HashMap::new()));
    }

    #[test]
    fn resource_attributes_match() {
        let m = ResourceMatcher {
            resource_type: String::new(),
            attributes: HashMap::from([("team".into(), "platform".into())]),
        };
        let attrs = HashMap::from([("team".into(), "platform".into())]);
        assert!(m.matches("any", &attrs));
        assert!(!m.matches("any", &HashMap::new()));
    }

    #[test]
    fn action_wildcard() {
        let m = ActionMatcher::default();
        assert!(m.matches("anything"));
    }

    #[test]
    fn action_or_match() {
        let m = ActionMatcher {
            names: vec!["read".into(), "list".into()],
        };
        assert!(m.matches("read"));
        assert!(m.matches("READ"));
        assert!(m.matches("list"));
        assert!(!m.matches("write"));
    }

    #[test]
    fn time_window_normal() {
        let tw = TimeWindow {
            after: Some("09:00".into()),
            before: Some("17:00".into()),
        };
        assert!(tw.contains(9, 0));
        assert!(tw.contains(12, 30));
        assert!(!tw.contains(17, 0));
        assert!(!tw.contains(8, 59));
    }

    #[test]
    fn time_window_overnight() {
        let tw = TimeWindow {
            after: Some("22:00".into()),
            before: Some("06:00".into()),
        };
        assert!(tw.contains(22, 0));
        assert!(tw.contains(23, 59));
        assert!(tw.contains(0, 0));
        assert!(tw.contains(5, 59));
        assert!(!tw.contains(6, 0));
        assert!(!tw.contains(12, 0));
    }

    #[test]
    fn time_window_after_only() {
        let tw = TimeWindow {
            after: Some("14:00".into()),
            before: None,
        };
        assert!(tw.contains(14, 0));
        assert!(tw.contains(23, 59));
        assert!(!tw.contains(13, 59));
    }

    #[test]
    fn time_window_before_only() {
        let tw = TimeWindow {
            after: None,
            before: Some("12:00".into()),
        };
        assert!(tw.contains(0, 0));
        assert!(tw.contains(11, 59));
        assert!(!tw.contains(12, 0));
        assert!(!tw.contains(18, 0));
    }

    #[test]
    fn time_window_both_none() {
        let tw = TimeWindow {
            after: None,
            before: None,
        };
        assert!(tw.contains(0, 0));
        assert!(tw.contains(12, 0));
        assert!(tw.contains(23, 59));
    }

    #[test]
    fn time_window_invalid_format() {
        let tw = TimeWindow {
            after: Some("not-a-time".into()),
            before: Some("17:00".into()),
        };
        // Invalid after parses to None, so only before applies
        assert!(tw.contains(10, 0));
        assert!(!tw.contains(18, 0));
    }

    #[test]
    fn conditions_with_satisfied_window() {
        let c = Conditions {
            time_window: Some(TimeWindow {
                after: Some("00:00".into()),
                before: Some("23:59".into()),
            }),
        };
        assert!(c.satisfied(12, 0));
    }

    #[test]
    fn conditions_with_unsatisfied_window() {
        let c = Conditions {
            time_window: Some(TimeWindow {
                after: Some("02:00".into()),
                before: Some("03:00".into()),
            }),
        };
        assert!(!c.satisfied(12, 0));
        assert!(c.satisfied(2, 30));
    }

    #[test]
    fn conditions_no_window() {
        let c = Conditions::default();
        assert!(c.satisfied(12, 0));
    }

    #[test]
    fn principal_role_case_insensitive() {
        let m = PrincipalMatcher {
            roles: vec!["Admin".into()],
            claims: HashMap::new(),
        };
        assert!(m.matches(&["admin".into()], &HashMap::new()));
        assert!(m.matches(&["ADMIN".into()], &HashMap::new()));
    }

    #[test]
    fn principal_role_and_claims_combined() {
        let m = PrincipalMatcher {
            roles: vec!["editor".into()],
            claims: HashMap::from([("dept".into(), "eng".into())]),
        };
        // Has role but wrong claim
        let wrong_claim = HashMap::from([("dept".into(), "sales".into())]);
        assert!(!m.matches(&["editor".into()], &wrong_claim));

        // Has claim but wrong role
        let right_claim = HashMap::from([("dept".into(), "eng".into())]);
        assert!(!m.matches(&["viewer".into()], &right_claim));

        // Both match
        assert!(m.matches(&["editor".into()], &right_claim));
    }

    #[test]
    fn principal_claims_wrong_value() {
        let m = PrincipalMatcher {
            roles: Vec::new(),
            claims: HashMap::from([("dept".into(), "eng".into())]),
        };
        let wrong = HashMap::from([("dept".into(), "sales".into())]);
        assert!(!m.matches(&[], &wrong));
    }

    #[test]
    fn principal_claims_missing_key() {
        let m = PrincipalMatcher {
            roles: Vec::new(),
            claims: HashMap::from([("dept".into(), "eng".into())]),
        };
        assert!(!m.matches(&[], &HashMap::new()));
    }

    #[test]
    fn resource_type_and_attributes_combined() {
        let m = ResourceMatcher {
            resource_type: "document".into(),
            attributes: HashMap::from([("classification".into(), "secret".into())]),
        };
        let attrs = HashMap::from([("classification".into(), "secret".into())]);
        assert!(m.matches("document", &attrs));
        assert!(!m.matches("endpoint", &attrs)); // wrong type
        assert!(!m.matches("document", &HashMap::new())); // missing attr
    }

    #[test]
    fn resource_attributes_wrong_value() {
        let m = ResourceMatcher {
            resource_type: String::new(),
            attributes: HashMap::from([("team".into(), "platform".into())]),
        };
        let wrong = HashMap::from([("team".into(), "mobile".into())]);
        assert!(!m.matches("any", &wrong));
    }

    #[test]
    fn parse_hhmm_valid() {
        assert_eq!(parse_hhmm("00:00"), Some(0));
        assert_eq!(parse_hhmm("23:59"), Some(23 * 60 + 59));
        assert_eq!(parse_hhmm("12:30"), Some(12 * 60 + 30));
    }

    #[test]
    fn parse_hhmm_invalid() {
        assert_eq!(parse_hhmm("24:00"), None);
        assert_eq!(parse_hhmm("12:60"), None);
        assert_eq!(parse_hhmm("abc"), None);
        assert_eq!(parse_hhmm("12:30:00"), None);
        assert_eq!(parse_hhmm(""), None);
    }
}
