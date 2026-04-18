//! `PolicyEvaluator` impl for `SentryClient`.
//!
//! Makes the remote TCP client a first-class `shroudb_acl::PolicyEvaluator`.
//! Any engine that holds `Arc<dyn PolicyEvaluator>` can delegate
//! authorization decisions to Sentry over the network identically to how
//! it delegates to an in-process `SentryEngine`. This is the pattern
//! commons/`shroudb-engine-bootstrap` will use for remote-mode policy
//! dispatch.

use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use shroudb_acl::{AclError, PolicyDecision, PolicyEffect, PolicyEvaluator, PolicyRequest};

use crate::SentryClient;

impl PolicyEvaluator for SentryClient {
    fn evaluate(
        &self,
        request: &PolicyRequest,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, AclError>> + Send + '_>> {
        // Serialize eagerly so the async block captures owned data only.
        let request_json = match serde_json::to_string(request) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("sentry client policy request serialization failed: {e}");
                return Box::pin(async move { Err(AclError::Internal(msg)) });
            }
        };
        Box::pin(async move {
            let result = self
                .evaluate(&request_json)
                .await
                .map_err(|e| AclError::Internal(format!("sentry evaluate failed: {e}")))?;
            let effect = PolicyEffect::from_str(&result.decision)
                .map_err(|e| AclError::Internal(format!("sentry decision parse: {e}")))?;
            Ok(PolicyDecision {
                effect,
                matched_policy: result.matched_policy,
                token: if result.token.is_empty() {
                    None
                } else {
                    Some(result.token)
                },
                cache_until: if result.cache_until == 0 {
                    None
                } else {
                    Some(result.cache_until)
                },
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn sentry_client_is_object_safe_under_policy_evaluator() {
        // Compile-only: if the impl goes away or gets the wrong shape
        // (e.g. reverts to `&mut self`), this line fails to compile.
        fn _accepts(_p: Arc<dyn PolicyEvaluator>) {}
        fn _would_accept(client: SentryClient) {
            _accepts(Arc::new(client));
        }
    }
}
