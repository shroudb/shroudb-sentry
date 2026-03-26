//! HTTP API server for policy evaluation, JWKS, and health checks.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use tower_http::cors::{AllowOrigin, CorsLayer};

use shroudb_sentry_core::evaluation::EvaluationRequest;
use shroudb_sentry_core::policy::PolicySet;

use shroudb_sentry_protocol::signing_index::SigningIndex;

#[derive(Clone)]
struct HttpState {
    policy_set: Arc<std::sync::RwLock<PolicySet>>,
    signing_index: Arc<SigningIndex>,
    default_decision: shroudb_sentry_core::policy::Effect,
    max_batch_size: usize,
    auth_registry: Arc<shroudb_sentry_protocol::auth::AuthRegistry>,
}

/// Configuration for the HTTP API server.
pub struct HttpConfig {
    pub bind: SocketAddr,
    pub policy_set: Arc<std::sync::RwLock<PolicySet>>,
    pub signing_index: Arc<SigningIndex>,
    pub default_decision: shroudb_sentry_core::policy::Effect,
    pub max_batch_size: usize,
    pub auth_registry: Arc<shroudb_sentry_protocol::auth::AuthRegistry>,
    pub cors_origins: Option<Vec<String>>,
}

/// Start the HTTP API server.
pub async fn run_http_server(
    config: HttpConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let cors_origins = config.cors_origins;
    let bind = config.bind;
    let state = HttpState {
        policy_set: config.policy_set,
        signing_index: config.signing_index,
        default_decision: config.default_decision,
        max_batch_size: config.max_batch_size,
        auth_registry: config.auth_registry,
    };

    let cors_layer = build_cors_layer(cors_origins);

    let app = Router::new()
        .route("/evaluate", post(post_evaluate))
        .route("/batch-evaluate", post(post_batch_evaluate))
        .route("/policies", get(get_policies))
        .route("/policies/{name}", get(get_policy))
        .route("/.well-known/jwks.json", get(get_jwks))
        .route("/health", get(get_health))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_middleware,
        ))
        .layer(cors_layer)
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

/// POST /batch-evaluate — evaluate multiple authorization requests in a single call.
async fn post_batch_evaluate(State(state): State<HttpState>, body: String) -> impl IntoResponse {
    #[derive(serde::Deserialize)]
    struct BatchRequest {
        evaluations: Vec<EvaluationRequest>,
    }

    let batch: BatchRequest = match serde_json::from_str(&body) {
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

    if batch.evaluations.len() > state.max_batch_size {
        return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "error": format!(
                    "batch size {} exceeds maximum {}",
                    batch.evaluations.len(),
                    state.max_batch_size
                )
            })
            .to_string(),
        )
            .into_response();
    }

    let ps = state.policy_set.read().expect("policy set lock poisoned");
    let mut results = Vec::with_capacity(batch.evaluations.len());

    for request in &batch.evaluations {
        let decision = ps.evaluate(request, state.default_decision);
        match state.signing_index.sign_decision(&decision, request) {
            Ok(signed) => {
                results.push(serde_json::json!({
                    "decision": signed.decision.to_string(),
                    "token": signed.token,
                    "policy": signed.matched_policy,
                    "cache_until": signed.cache_until,
                }));
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::json!({ "error": format!("signing error: {e}") }).to_string(),
                )
                    .into_response();
            }
        }
    }

    drop(ps);

    let response = serde_json::json!({ "results": results });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        response.to_string(),
    )
        .into_response()
}

/// Bearer token auth middleware for HTTP API.
async fn bearer_auth_middleware(
    State(state): State<HttpState>,
    req: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    // Skip auth for health and JWKS endpoints.
    let path = req.uri().path();
    if path == "/health" || path == "/.well-known/jwks.json" {
        return next.run(req).await;
    }

    // If auth is not required, pass through.
    if !state.auth_registry.is_required() {
        return next.run(req).await;
    }

    // Check Authorization header.
    let auth_header = req.headers().get(header::AUTHORIZATION);
    match auth_header.and_then(|v| v.to_str().ok()) {
        Some(value) if value.starts_with("Bearer ") => {
            let token = &value[7..];
            match state.auth_registry.authenticate(token) {
                Ok(_policy) => next.run(req).await,
                Err(_) => (
                    StatusCode::UNAUTHORIZED,
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"error":"invalid token"}"#,
                )
                    .into_response(),
            }
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":"authorization required"}"#,
        )
            .into_response(),
    }
}

/// Build CORS layer from config.
fn build_cors_layer(origins: Option<Vec<String>>) -> CorsLayer {
    let allow_origin = match origins {
        Some(ref origins) if !origins.is_empty() => {
            let origins: Vec<axum::http::HeaderValue> =
                origins.iter().filter_map(|o| o.parse().ok()).collect();
            AllowOrigin::list(origins)
        }
        _ => AllowOrigin::any(),
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
}
