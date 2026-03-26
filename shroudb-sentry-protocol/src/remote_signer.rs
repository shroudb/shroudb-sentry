//! Remote signer: connects to a Core server to sign decisions over TCP.
//!
//! For JWT: sends `ISSUE <keyspace> CLAIMS <json> TTL <secs>`.
//! For JWKS: sends `JWKS <keyspace>`.

use std::io;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use shroudb_sentry_core::decision::{Decision, SignedDecision, SignedDecisionClaims};
use shroudb_sentry_core::error::SentryError;
use shroudb_sentry_core::evaluation::EvaluationRequest;
use shroudb_sentry_core::signing::DecisionSigner;

/// Configuration for the remote signer.
#[derive(Debug, Clone)]
pub struct RemoteSignerConfig {
    pub uri: String,
    pub keyspace: String,
}

/// A signer that delegates to a remote Core server over TCP.
pub struct RemoteSigner {
    connection: Mutex<RemoteConnection>,
    keyspace: String,
}

struct RemoteConnection {
    reader: BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
    writer: BufWriter<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>,
}

impl RemoteSigner {
    /// Connect to a remote Core server.
    pub async fn connect(config: &RemoteSignerConfig) -> Result<Self, SentryError> {
        let stream = TcpStream::connect(&config.uri)
            .await
            .map_err(|e| SentryError::SigningError(format!("remote connection failed: {e}")))?;
        let (r, w) = tokio::io::split(stream);
        let connection = RemoteConnection {
            reader: BufReader::new(Box::new(r)),
            writer: BufWriter::new(Box::new(w)),
        };
        Ok(Self {
            connection: Mutex::new(connection),
            keyspace: config.keyspace.clone(),
        })
    }

    async fn send_command(&self, args: &[&str]) -> Result<String, SentryError> {
        let mut conn = self.connection.lock().await;

        // Write command frame.
        conn.writer
            .write_all(format!("*{}\r\n", args.len()).as_bytes())
            .await
            .map_err(io_to_sentry)?;
        for arg in args {
            let bytes = arg.as_bytes();
            conn.writer
                .write_all(format!("${}\r\n", bytes.len()).as_bytes())
                .await
                .map_err(io_to_sentry)?;
            conn.writer.write_all(bytes).await.map_err(io_to_sentry)?;
            conn.writer.write_all(b"\r\n").await.map_err(io_to_sentry)?;
        }
        conn.writer.flush().await.map_err(io_to_sentry)?;

        // Read response (simple: read first line to get type).
        let mut line = String::new();
        conn.reader
            .read_line(&mut line)
            .await
            .map_err(io_to_sentry)?;
        let line = line.trim_end();

        if line.is_empty() {
            return Err(SentryError::SigningError(
                "empty response from remote signer".into(),
            ));
        }

        match line.as_bytes()[0] {
            b'+' => Ok(line[1..].to_string()),
            b'-' => Err(SentryError::SigningError(format!(
                "remote error: {}",
                &line[1..]
            ))),
            b'$' => {
                let len: usize = line[1..]
                    .parse()
                    .map_err(|e| SentryError::SigningError(format!("bad bulk length: {e}")))?;
                let mut buf = vec![0u8; len + 2]; // +2 for \r\n
                conn.reader
                    .read_exact(&mut buf)
                    .await
                    .map_err(io_to_sentry)?;
                String::from_utf8(buf[..len].to_vec())
                    .map_err(|e| SentryError::SigningError(format!("invalid UTF-8: {e}")))
            }
            _ => Err(SentryError::SigningError(format!(
                "unexpected response type: {line}"
            ))),
        }
    }
}

fn io_to_sentry(e: io::Error) -> SentryError {
    SentryError::SigningError(format!("remote I/O error: {e}"))
}

impl DecisionSigner for RemoteSigner {
    fn sign(
        &self,
        decision: &Decision,
        request: &EvaluationRequest,
        now: u64,
        ttl_secs: u64,
    ) -> Result<SignedDecision, SentryError> {
        // Build claims JSON.
        let exp = now + ttl_secs;
        let claims = SignedDecisionClaims {
            decision: decision.effect.to_string(),
            principal: request.principal.id.clone(),
            resource: request.resource.id.clone(),
            action: request.action.clone(),
            policy: decision.matched_policy.clone(),
            iat: now,
            exp,
        };
        let claims_json =
            serde_json::to_string(&claims).map_err(|e| SentryError::SigningError(e.to_string()))?;
        let ttl_str = ttl_secs.to_string();

        // This is a synchronous trait method, but we need async.
        // Use a blocking approach via tokio::task::block_in_place.
        let keyspace = self.keyspace.clone();
        let token = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.send_command(&["ISSUE", &keyspace, "CLAIMS", &claims_json, "TTL", &ttl_str])
                    .await
            })
        })?;

        Ok(SignedDecision {
            decision: decision.effect,
            token,
            matched_policy: decision.matched_policy.clone(),
            cache_until: exp,
        })
    }

    fn jwks(&self) -> Result<serde_json::Value, SentryError> {
        let keyspace = self.keyspace.clone();
        let response = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.send_command(&["JWKS", &keyspace]).await })
        })?;

        serde_json::from_str(&response)
            .map_err(|e| SentryError::SigningError(format!("invalid JWKS JSON: {e}")))
    }
}
