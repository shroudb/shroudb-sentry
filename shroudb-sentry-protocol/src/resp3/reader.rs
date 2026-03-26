use std::pin::Pin;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

use super::{ProtocolError, Resp3Frame};

/// Maximum bulk string size: 16 MiB.
const MAX_BULK_SIZE: usize = 16 * 1024 * 1024;

/// Maximum nesting depth for arrays and maps.
const MAX_DEPTH: u8 = 8;

/// Read a single RESP3 frame from the async buffered reader.
///
/// Returns `Ok(None)` on a clean EOF (no bytes available).
pub async fn read_frame(
    reader: &mut (impl AsyncBufRead + Unpin + Send),
) -> Result<Option<Resp3Frame>, ProtocolError> {
    read_frame_depth(reader, 0).await
}

fn read_frame_depth<'a>(
    reader: &'a mut (dyn AsyncBufRead + Unpin + Send),
    depth: u8,
) -> Pin<Box<dyn std::future::Future<Output = Result<Option<Resp3Frame>, ProtocolError>> + Send + 'a>>
{
    Box::pin(async move {
        if depth > MAX_DEPTH {
            return Err(ProtocolError::NestingTooDeep);
        }

        // Peek for EOF
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(None);
        }

        let type_byte = {
            let mut b = [0u8; 1];
            reader.read_exact(&mut b).await?;
            b[0]
        };

        match type_byte {
            b'+' => {
                let line = read_line(reader).await?;
                Ok(Some(Resp3Frame::SimpleString(line)))
            }
            b'-' => {
                let line = read_line(reader).await?;
                Ok(Some(Resp3Frame::SimpleError(line)))
            }
            b':' => {
                let line = read_line(reader).await?;
                let n = line
                    .parse::<i64>()
                    .map_err(|e| ProtocolError::InvalidFormat(format!("bad integer: {e}")))?;
                Ok(Some(Resp3Frame::Integer(n)))
            }
            b'$' => {
                let line = read_line(reader).await?;
                let len: usize = line
                    .parse()
                    .map_err(|e| ProtocolError::InvalidFormat(format!("bad bulk length: {e}")))?;
                if len > MAX_BULK_SIZE {
                    return Err(ProtocolError::FrameTooLarge(len));
                }
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf).await?;
                // consume trailing \r\n
                let mut crlf = [0u8; 2];
                reader.read_exact(&mut crlf).await?;
                if crlf != *b"\r\n" {
                    return Err(ProtocolError::InvalidFormat(
                        "missing CRLF after bulk string".into(),
                    ));
                }
                Ok(Some(Resp3Frame::BulkString(buf)))
            }
            b'*' => {
                let line = read_line(reader).await?;
                let count: usize = line
                    .parse()
                    .map_err(|e| ProtocolError::InvalidFormat(format!("bad array length: {e}")))?;
                let mut frames = Vec::with_capacity(count);
                for _ in 0..count {
                    match read_frame_depth(reader, depth + 1).await? {
                        Some(f) => frames.push(f),
                        None => {
                            return Err(ProtocolError::InvalidFormat(
                                "unexpected EOF in array".into(),
                            ));
                        }
                    }
                }
                Ok(Some(Resp3Frame::Array(frames)))
            }
            b'%' => {
                let line = read_line(reader).await?;
                let count: usize = line
                    .parse()
                    .map_err(|e| ProtocolError::InvalidFormat(format!("bad map length: {e}")))?;
                let mut pairs = Vec::with_capacity(count);
                for _ in 0..count {
                    let key = match read_frame_depth(reader, depth + 1).await? {
                        Some(f) => f,
                        None => {
                            return Err(ProtocolError::InvalidFormat(
                                "unexpected EOF in map key".into(),
                            ));
                        }
                    };
                    let value = match read_frame_depth(reader, depth + 1).await? {
                        Some(f) => f,
                        None => {
                            return Err(ProtocolError::InvalidFormat(
                                "unexpected EOF in map value".into(),
                            ));
                        }
                    };
                    pairs.push((key, value));
                }
                Ok(Some(Resp3Frame::Map(pairs)))
            }
            b'_' => {
                // Null: read the trailing \r\n
                let mut crlf = [0u8; 2];
                reader.read_exact(&mut crlf).await?;
                if crlf != *b"\r\n" {
                    return Err(ProtocolError::InvalidFormat(
                        "missing CRLF after null".into(),
                    ));
                }
                Ok(Some(Resp3Frame::Null))
            }
            other => Err(ProtocolError::InvalidTypeByte(other)),
        }
    })
}

/// Read a line terminated by `\r\n` and return its contents without the terminator.
async fn read_line(
    reader: &mut (dyn AsyncBufRead + Unpin + Send),
) -> Result<String, ProtocolError> {
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;

    async fn parse(input: &[u8]) -> Option<Resp3Frame> {
        let mut reader = BufReader::new(Cursor::new(input.to_vec()));
        read_frame(&mut reader).await.unwrap()
    }

    #[tokio::test]
    async fn read_simple_string() {
        let frame = parse(b"+OK\r\n").await.unwrap();
        assert_eq!(frame, Resp3Frame::SimpleString("OK".into()));
    }

    #[tokio::test]
    async fn read_simple_error() {
        let frame = parse(b"-ERR bad\r\n").await.unwrap();
        assert_eq!(frame, Resp3Frame::SimpleError("ERR bad".into()));
    }

    #[tokio::test]
    async fn read_integer() {
        let frame = parse(b":42\r\n").await.unwrap();
        assert_eq!(frame, Resp3Frame::Integer(42));
    }

    #[tokio::test]
    async fn read_bulk_string() {
        let frame = parse(b"$5\r\nhello\r\n").await.unwrap();
        assert_eq!(frame, Resp3Frame::BulkString(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn read_null() {
        let frame = parse(b"_\r\n").await.unwrap();
        assert_eq!(frame, Resp3Frame::Null);
    }

    #[tokio::test]
    async fn read_array() {
        let frame = parse(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n").await.unwrap();
        assert_eq!(
            frame,
            Resp3Frame::Array(vec![
                Resp3Frame::BulkString(b"foo".to_vec()),
                Resp3Frame::BulkString(b"bar".to_vec()),
            ])
        );
    }

    #[tokio::test]
    async fn read_eof_returns_none() {
        let result = parse(b"").await;
        assert!(result.is_none());
    }
}
