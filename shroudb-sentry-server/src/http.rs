//! HTTP server for Prometheus metrics and JWKS endpoint.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;

use shroudb_sentry_protocol::signing_index::SigningIndex;

#[derive(Clone)]
struct HttpState {
    signing_index: Arc<SigningIndex>,
    metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
}

/// Configuration for the HTTP server.
pub struct HttpConfig {
    pub bind: SocketAddr,
    pub signing_index: Arc<SigningIndex>,
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
}

/// Start the HTTP server.
pub async fn run_http_server(
    config: HttpConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let bind = config.bind;
    let state = HttpState {
        signing_index: config.signing_index,
        metrics_handle: config.metrics_handle,
    };

    let app = Router::new()
        .route("/.well-known/jwks.json", get(get_jwks))
        .route("/metrics", get(get_metrics))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(addr = %bind, "HTTP server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
        })
        .await?;

    Ok(())
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

/// GET /metrics — Prometheus metrics.
async fn get_metrics(State(state): State<HttpState>) -> impl IntoResponse {
    let metrics = state.metrics_handle.render();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        metrics,
    )
}
