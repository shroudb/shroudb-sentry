use std::sync::Arc;
use std::time::Instant;

use metrics::{counter, gauge};
use shroudb_sentry_protocol::auth::AuthPolicy;
use shroudb_sentry_protocol::resp3::parse_command::parse_command;
use shroudb_sentry_protocol::resp3::reader::read_frame;
use shroudb_sentry_protocol::resp3::writer::write_frame;
use shroudb_sentry_protocol::serialize::response_to_frame;
use shroudb_sentry_protocol::{Command, CommandDispatcher, CommandResponse, Resp3Frame};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::watch;

struct ConnectionGuard;

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        gauge!("sentry_concurrent_connections").decrement(1.0);
    }
}

struct RateLimiter {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub async fn handle_connection(
    stream: impl tokio::io::AsyncRead + AsyncWrite + Unpin + Send + 'static,
    dispatcher: Arc<CommandDispatcher>,
    mut shutdown_rx: watch::Receiver<bool>,
    rate_limit: Option<u32>,
) {
    gauge!("sentry_concurrent_connections").increment(1.0);
    let _conn_guard = ConnectionGuard;

    let (reader_half, writer_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader_half);
    let mut writer = BufWriter::new(writer_half);

    let mut rate_limiter = rate_limit.map(|limit| RateLimiter::new(limit as f64, limit as f64));
    let mut auth: Option<AuthPolicy> = None;

    loop {
        let frame = tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::debug!("connection shutting down by signal");
                    break;
                }
                continue;
            }
            result = read_frame(&mut reader) => result,
        };

        let frame = match frame {
            Ok(Some(f)) => f,
            Ok(None) => {
                tracing::debug!("client disconnected (EOF)");
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, "protocol error reading frame");
                let err_frame = Resp3Frame::SimpleError(format!("ERR protocol: {e}"));
                if write_frame(&mut writer, &err_frame).await.is_err()
                    || writer.flush().await.is_err()
                {
                    tracing::debug!("could not send protocol error reply");
                }
                break;
            }
        };

        let command = match parse_command(frame) {
            Ok(cmd) => cmd,
            Err(e) => {
                let err_frame = Resp3Frame::SimpleError(format!("ERR {e}"));
                if write_frame(&mut writer, &err_frame).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
                continue;
            }
        };

        if let Some(ref mut limiter) = rate_limiter
            && !limiter.try_acquire()
        {
            let response = CommandResponse::Error(shroudb_sentry_protocol::CommandError::Denied {
                reason: "rate limit exceeded".into(),
            });
            let response_frame = response_to_frame(&response);
            if write_frame(&mut writer, &response_frame).await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
            continue;
        }

        // Handle AUTH at the connection level.
        if let Command::Auth { ref token } = command {
            match dispatcher.auth_registry().authenticate(token) {
                Ok(policy) => {
                    counter!("sentry_auth_total", "result" => "ok").increment(1);
                    auth = Some(policy.clone());
                    let response =
                        CommandResponse::Success(shroudb_sentry_protocol::ResponseMap::ok());
                    let response_frame = response_to_frame(&response);
                    if write_frame(&mut writer, &response_frame).await.is_err() {
                        break;
                    }
                    if writer.flush().await.is_err() {
                        break;
                    }
                    continue;
                }
                Err(e) => {
                    counter!("sentry_auth_total", "result" => "denied").increment(1);
                    let response = CommandResponse::Error(e);
                    let response_frame = response_to_frame(&response);
                    if write_frame(&mut writer, &response_frame).await.is_err() {
                        break;
                    }
                    if writer.flush().await.is_err() {
                        break;
                    }
                    continue;
                }
            }
        }

        let response = dispatcher.execute(command, auth.as_ref()).await;

        let response_frame = response_to_frame(&response);
        if write_frame(&mut writer, &response_frame).await.is_err() {
            tracing::debug!("write error, closing connection");
            break;
        }
        if writer.flush().await.is_err() {
            tracing::debug!("flush error, closing connection");
            break;
        }
    }
}
