use std::sync::Arc;

use shroudb_acl::{AclRequirement, AuthContext, TokenValidator};
use shroudb_protocol_wire::Resp3Frame;
use shroudb_protocol_wire::reader::read_frame;
use shroudb_protocol_wire::writer::write_frame;
use shroudb_store::Store;
use tokio::io::BufReader;
use tokio::net::TcpListener;

use shroudb_sentry_engine::engine::SentryEngine;
use shroudb_sentry_protocol::commands::{SentryCommand, parse_command};
use shroudb_sentry_protocol::dispatch;
use shroudb_sentry_protocol::response::SentryResponse;

pub async fn run_tcp<S: Store + 'static>(
    listener: TcpListener,
    engine: Arc<SentryEngine<S>>,
    token_validator: Option<Arc<dyn TokenValidator>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        let engine = engine.clone();
                        let validator = token_validator.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, &engine, validator.as_deref()).await {
                                tracing::debug!(%addr, error = %e, "connection closed");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "TCP accept error");
                    }
                }
            }
        }
    }
}

async fn handle_connection<S: Store>(
    stream: tokio::net::TcpStream,
    engine: &SentryEngine<S>,
    token_validator: Option<&dyn TokenValidator>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let mut auth_context: Option<AuthContext> = None;
    let auth_required = token_validator.is_some();

    loop {
        // Read RESP3 frame
        let frame = match read_frame(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()), // EOF
            Err(e) => {
                let err_frame = Resp3Frame::SimpleError(format!("ERR {e}"));
                let _ = write_frame(&mut writer, &err_frame).await;
                return Err(Box::new(e) as Box<dyn std::error::Error>);
            }
        };

        // Convert frame to string args
        let args = match frame_to_args(&frame) {
            Ok(args) => args,
            Err(e) => {
                let err_frame = Resp3Frame::SimpleError(format!("ERR {e}"));
                let _ = write_frame(&mut writer, &err_frame).await;
                continue;
            }
        };

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        // Parse command
        let cmd = match parse_command(&arg_refs) {
            Ok(cmd) => cmd,
            Err(e) => {
                let resp = response_to_frame(&SentryResponse::error(e));
                write_frame(&mut writer, &resp).await?;
                continue;
            }
        };

        // Handle AUTH at connection layer
        if let SentryCommand::Auth { ref token } = cmd {
            if let Some(validator) = token_validator {
                match validator.validate(token) {
                    Ok(tok) => {
                        auth_context = Some(tok.into_context());
                        let resp = response_to_frame(&SentryResponse::ok_simple());
                        write_frame(&mut writer, &resp).await?;
                    }
                    Err(e) => {
                        let resp =
                            response_to_frame(&SentryResponse::error(format!("auth failed: {e}")));
                        write_frame(&mut writer, &resp).await?;
                    }
                }
            } else {
                let resp = response_to_frame(&SentryResponse::ok_simple());
                write_frame(&mut writer, &resp).await?;
            }
            continue;
        }

        // Check if auth required but not authenticated
        if auth_required && auth_context.is_none() && cmd.acl_requirement() != AclRequirement::None
        {
            let resp = response_to_frame(&SentryResponse::error(
                "authentication required — send AUTH <token> first",
            ));
            write_frame(&mut writer, &resp).await?;
            continue;
        }

        // Dispatch to engine
        let response = dispatch::dispatch(engine, cmd, auth_context.as_ref()).await;
        let resp_frame = response_to_frame(&response);
        write_frame(&mut writer, &resp_frame).await?;
    }
}

fn frame_to_args(frame: &Resp3Frame) -> Result<Vec<String>, String> {
    match frame {
        Resp3Frame::Array(items) => {
            let mut args = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Resp3Frame::BulkString(bytes) => {
                        args.push(
                            String::from_utf8(bytes.clone())
                                .map_err(|e| format!("invalid UTF-8: {e}"))?,
                        );
                    }
                    Resp3Frame::SimpleString(s) => {
                        args.push(s.clone());
                    }
                    _ => return Err("expected string arguments".into()),
                }
            }
            Ok(args)
        }
        _ => Err("expected array command".into()),
    }
}

fn response_to_frame(response: &SentryResponse) -> Resp3Frame {
    match response {
        SentryResponse::Ok(data) => {
            let json = serde_json::to_string(data).unwrap_or_default();
            Resp3Frame::BulkString(json.into_bytes())
        }
        SentryResponse::Error(msg) => Resp3Frame::SimpleError(format!("ERR {msg}")),
    }
}
