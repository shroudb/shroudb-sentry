use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::evaluation::{Principal, Resource};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrincipalMatcher {
    pub role: Option<Vec<String>>,
    #[serde(default)]
    pub claims: HashMap<String, ClaimValue>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceMatcher {
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionMatcher {
    pub name: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Array(Vec<String>),
}

/// Optional conditions for advanced policy evaluation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conditions {
    #[serde(default)]
    pub time_window: Option<TimeWindow>,
}

/// Time-based condition: policy only applies within a time window.
///
/// Times are in "HH:MM" format (UTC). If `after` > `before`, the window wraps
/// overnight (e.g., `after = "22:00"`, `before = "06:00"` means 10 PM to 6 AM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub after: Option<String>,
    pub before: Option<String>,
}

/// Parse "HH:MM" to minutes since midnight.
fn parse_hhmm(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let hours: u32 = parts[0].parse().ok()?;
    let minutes: u32 = parts[1].parse().ok()?;
    if hours >= 24 || minutes >= 60 {
        return None;
    }
    Some(hours * 60 + minutes)
}

impl Conditions {
    /// Evaluate all conditions. Returns `true` if all conditions are met.
    pub fn evaluate(&self, now_utc_minutes: u32) -> bool {
        if let Some(ref tw) = self.time_window
            && !tw.is_within(now_utc_minutes)
        {
            return false;
        }
        true
    }
}

impl TimeWindow {
    /// Check if the given time (minutes since midnight UTC) falls within this window.
    pub fn is_within(&self, now_minutes: u32) -> bool {
        let after = self.after.as_deref().and_then(parse_hhmm);
        let before = self.before.as_deref().and_then(parse_hhmm);

        match (after, before) {
            (Some(a), Some(b)) => {
                if a <= b {
                    // Normal window: after <= now < before
                    now_minutes >= a && now_minutes < b
                } else {
                    // Overnight wrap: now >= after OR now < before
                    now_minutes >= a || now_minutes < b
                }
            }
            (Some(a), None) => now_minutes >= a,
            (None, Some(b)) => now_minutes < b,
            (None, None) => true,
        }
    }
}

/// Get current UTC time as minutes since midnight.
pub fn current_utc_minutes() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs_today = secs % 86400;
    (secs_today / 60) as u32
}

impl PrincipalMatcher {
    /// Check if this matcher matches the given principal.
    ///
    /// Role matching uses OR (any role matches). Claims use AND (all must match).
    /// An empty matcher is a wildcard (matches everything).
    pub fn matches(&self, principal: &Principal) -> bool {
        // Role check: OR semantics — any role match is sufficient.
        if let Some(ref roles) = self.role
            && !roles.is_empty()
        {
            let has_match = roles
                .iter()
                .any(|r| principal.roles.iter().any(|pr| pr == r));
            if !has_match {
                return false;
            }
        }

        // Claims check: AND semantics — all claims must match.
        for (key, expected) in &self.claims {
            match principal.claims.get(key) {
                Some(actual) => {
                    if !claim_matches(expected, actual) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

impl ResourceMatcher {
    /// Check if this matcher matches the given resource.
    ///
    /// Type is exact match. Attributes are exact match per key.
    /// Empty matcher is a wildcard.
    pub fn matches(&self, resource: &Resource) -> bool {
        if let Some(ref rt) = self.resource_type
            && rt != &resource.resource_type
        {
            return false;
        }

        for (key, expected) in &self.attributes {
            match resource.attributes.get(key) {
                Some(actual) => {
                    if expected != actual {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

impl ActionMatcher {
    /// Check if this matcher matches the given action.
    ///
    /// Name uses OR semantics. Empty matcher is a wildcard.
    pub fn matches(&self, action: &str) -> bool {
        if let Some(ref names) = self.name
            && !names.is_empty()
        {
            return names.iter().any(|n| n.eq_ignore_ascii_case(action));
        }
        true
    }
}

/// Compare a ClaimValue against a serde_json::Value.
fn claim_matches(expected: &ClaimValue, actual: &serde_json::Value) -> bool {
    match expected {
        ClaimValue::String(s) => actual.as_str().is_some_and(|v| v == s),
        ClaimValue::Integer(n) => actual.as_i64().is_some_and(|v| v == *n),
        ClaimValue::Boolean(b) => actual.as_bool().is_some_and(|v| v == *b),
        ClaimValue::Array(arr) => {
            // At least one element in expected must match actual
            // If actual is a string, check if it's in the expected array
            // If actual is an array, check intersection
            if let Some(s) = actual.as_str() {
                arr.iter().any(|e| e == s)
            } else if let Some(actual_arr) = actual.as_array() {
                arr.iter().any(|e| {
                    actual_arr
                        .iter()
                        .any(|a| a.as_str().is_some_and(|s| s == e))
                })
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(roles: &[&str], claims: &[(&str, serde_json::Value)]) -> Principal {
        Principal {
            id: "user1".into(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
            claims: claims
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        }
    }

    fn resource(rtype: &str, attrs: &[(&str, serde_json::Value)]) -> Resource {
        Resource {
            id: "res1".into(),
            resource_type: rtype.into(),
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        }
    }

    #[test]
    fn empty_principal_matcher_is_wildcard() {
        let m = PrincipalMatcher::default();
        let p = principal(&["admin"], &[]);
        assert!(m.matches(&p));
    }

    #[test]
    fn role_or_matching() {
        let m = PrincipalMatcher {
            role: Some(vec!["admin".into(), "editor".into()]),
            claims: HashMap::new(),
        };
        assert!(m.matches(&principal(&["admin"], &[])));
        assert!(m.matches(&principal(&["editor"], &[])));
        assert!(m.matches(&principal(&["admin", "viewer"], &[])));
        assert!(!m.matches(&principal(&["viewer"], &[])));
    }

    #[test]
    fn claims_and_matching() {
        let mut claims = HashMap::new();
        claims.insert("department".into(), ClaimValue::String("eng".into()));
        claims.insert("level".into(), ClaimValue::Integer(5));
        let m = PrincipalMatcher { role: None, claims };

        // Both match
        let p = principal(
            &[],
            &[
                ("department", serde_json::json!("eng")),
                ("level", serde_json::json!(5)),
            ],
        );
        assert!(m.matches(&p));

        // Missing one claim
        let p2 = principal(&[], &[("department", serde_json::json!("eng"))]);
        assert!(!m.matches(&p2));

        // Wrong value
        let p3 = principal(
            &[],
            &[
                ("department", serde_json::json!("sales")),
                ("level", serde_json::json!(5)),
            ],
        );
        assert!(!m.matches(&p3));
    }

    #[test]
    fn empty_resource_matcher_is_wildcard() {
        let m = ResourceMatcher::default();
        assert!(m.matches(&resource("document", &[])));
    }

    #[test]
    fn resource_type_exact_match() {
        let m = ResourceMatcher {
            resource_type: Some("document".into()),
            attributes: HashMap::new(),
        };
        assert!(m.matches(&resource("document", &[])));
        assert!(!m.matches(&resource("image", &[])));
    }

    #[test]
    fn resource_attribute_matching() {
        let mut attrs = HashMap::new();
        attrs.insert("classification".into(), serde_json::json!("secret"));
        let m = ResourceMatcher {
            resource_type: None,
            attributes: attrs,
        };
        assert!(m.matches(&resource(
            "doc",
            &[("classification", serde_json::json!("secret"))]
        )));
        assert!(!m.matches(&resource(
            "doc",
            &[("classification", serde_json::json!("public"))]
        )));
    }

    #[test]
    fn empty_action_matcher_is_wildcard() {
        let m = ActionMatcher::default();
        assert!(m.matches("read"));
    }

    #[test]
    fn action_or_matching() {
        let m = ActionMatcher {
            name: Some(vec!["read".into(), "list".into()]),
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
        assert!(tw.is_within(9 * 60)); // 09:00
        assert!(tw.is_within(12 * 60)); // 12:00
        assert!(!tw.is_within(17 * 60)); // 17:00 (exclusive)
        assert!(!tw.is_within(8 * 60)); // 08:00
        assert!(!tw.is_within(20 * 60)); // 20:00
    }

    #[test]
    fn time_window_overnight() {
        let tw = TimeWindow {
            after: Some("22:00".into()),
            before: Some("06:00".into()),
        };
        assert!(tw.is_within(23 * 60)); // 23:00
        assert!(tw.is_within(0)); // 00:00
        assert!(tw.is_within(5 * 60)); // 05:00
        assert!(!tw.is_within(6 * 60)); // 06:00 (exclusive)
        assert!(!tw.is_within(12 * 60)); // 12:00
    }

    #[test]
    fn time_window_after_only() {
        let tw = TimeWindow {
            after: Some("09:00".into()),
            before: None,
        };
        assert!(tw.is_within(9 * 60));
        assert!(tw.is_within(23 * 60));
        assert!(!tw.is_within(8 * 60));
    }

    #[test]
    fn time_window_before_only() {
        let tw = TimeWindow {
            after: None,
            before: Some("17:00".into()),
        };
        assert!(tw.is_within(0));
        assert!(tw.is_within(16 * 60));
        assert!(!tw.is_within(17 * 60));
    }

    #[test]
    fn time_window_empty() {
        let tw = TimeWindow {
            after: None,
            before: None,
        };
        assert!(tw.is_within(12 * 60));
    }

    #[test]
    fn conditions_evaluate_with_time() {
        let conditions = Conditions {
            time_window: Some(TimeWindow {
                after: Some("09:00".into()),
                before: Some("17:00".into()),
            }),
        };
        assert!(conditions.evaluate(12 * 60));
        assert!(!conditions.evaluate(20 * 60));
    }

    #[test]
    fn parse_hhmm_valid() {
        assert_eq!(parse_hhmm("00:00"), Some(0));
        assert_eq!(parse_hhmm("09:30"), Some(9 * 60 + 30));
        assert_eq!(parse_hhmm("23:59"), Some(23 * 60 + 59));
    }

    #[test]
    fn parse_hhmm_invalid() {
        assert_eq!(parse_hhmm("24:00"), None);
        assert_eq!(parse_hhmm("12:60"), None);
        assert_eq!(parse_hhmm("abc"), None);
        assert_eq!(parse_hhmm("12"), None);
    }

    #[test]
    fn claim_array_matching() {
        let mut claims = HashMap::new();
        claims.insert(
            "groups".into(),
            ClaimValue::Array(vec!["admin".into(), "ops".into()]),
        );
        let m = PrincipalMatcher { role: None, claims };

        // Actual is a string in the expected array
        let p = principal(&[], &[("groups", serde_json::json!("admin"))]);
        assert!(m.matches(&p));

        // Actual is an array with intersection
        let p2 = principal(&[], &[("groups", serde_json::json!(["ops", "dev"]))]);
        assert!(m.matches(&p2));

        // No intersection
        let p3 = principal(&[], &[("groups", serde_json::json!(["dev"]))]);
        assert!(!m.matches(&p3));
    }
}
