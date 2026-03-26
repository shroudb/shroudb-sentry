//! HTTP API server for policy evaluation, JWKS, and health checks.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};

use shroudb_sentry_core::evaluation::EvaluationRequest;
use shroudb_sentry_core::policy::PolicySet;

use shroudb_sentry_protocol::signing_index::SigningIndex;

#[derive(Clone)]
struct HttpState {
    policy_set: Arc<std::sync::RwLock<PolicySet>>,
    signing_index: Arc<SigningIndex>,
    default_decision: shroudb_sentry_core::policy::Effect,
}

/// Start the HTTP API server.
pub async fn run_http_server(
    bind: SocketAddr,
    policy_set: Arc<std::sync::RwLock<PolicySet>>,
    signing_index: Arc<SigningIndex>,
    default_decision: shroudb_sentry_core::policy::Effect,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let state = HttpState {
        policy_set,
        signing_index,
        default_decision,
    };

    let app = Router::new()
        .route("/evaluate", post(post_evaluate))
        .route("/policies", get(get_policies))
        .route("/policies/{name}", get(get_policy))
        .route("/.well-known/jwks.json", get(get_jwks))
        .route("/health", get(get_health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(addr = %bind, "HTTP API listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
        })
        .await?;

    Ok(())
}

/// POST /evaluate — evaluate an authorization request.
async fn post_evaluate(State(state): State<HttpState>, body: String) -> impl IntoResponse {
    let request: EvaluationRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "error": format!("invalid request: {e}") }).to_string(),
            )
                .into_response();
        }
    };

    let ps = state.policy_set.read().expect("policy set lock poisoned");
    let decision = ps.evaluate(&request, state.default_decision);
    drop(ps);

    let signed = match state.signing_index.sign_decision(&decision, &request) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "error": format!("signing error: {e}") }).to_string(),
            )
                .into_response();
        }
    };

    let response = serde_json::json!({
        "decision": signed.decision.to_string(),
        "token": signed.token,
        "policy": signed.matched_policy,
        "cache_until": signed.cache_until,
    });

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        response.to_string(),
    )
        .into_response()
}

/// GET /policies — list all loaded policies.
async fn get_policies(State(state): State<HttpState>) -> impl IntoResponse {
    let ps = state.policy_set.read().expect("policy set lock poisoned");
    let names: Vec<&str> = ps.policies().iter().map(|p| p.name.as_str()).collect();
    let response = serde_json::json!({
        "count": names.len(),
        "policies": names,
    });

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        response.to_string(),
    )
}

/// GET /policies/{name} — get details of a specific policy.
async fn get_policy(
    State(state): State<HttpState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    let ps = state.policy_set.read().expect("policy set lock poisoned");
    match ps.get(&name) {
        Some(policy) => {
            let response = serde_json::json!({
                "name": policy.name,
                "description": policy.description,
                "effect": policy.effect.to_string(),
                "priority": policy.priority,
            });
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                response.to_string(),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "error": "policy not found" }).to_string(),
        )
            .into_response(),
    }
}

/// GET /.well-known/jwks.json — JWKS endpoint for decision token verification.
async fn get_jwks(State(state): State<HttpState>) -> impl IntoResponse {
    match state.signing_index.jwks() {
        Ok(jwks) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "public, max-age=3600"),
            ],
            jwks.to_string(),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "error": format!("{e}") }).to_string(),
        )
            .into_response(),
    }
}

/// GET /health — health check.
async fn get_health() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"status":"ok"}"#,
    )
}
