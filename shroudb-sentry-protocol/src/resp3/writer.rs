use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::Resp3Frame;

/// Write a RESP3 frame to the async writer.
pub async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    frame: &Resp3Frame,
) -> Result<(), std::io::Error> {
    match frame {
        Resp3Frame::SimpleString(s) => {
            writer.write_all(b"+").await?;
            writer.write_all(s.as_bytes()).await?;
            writer.write_all(b"\r\n").await?;
        }
        Resp3Frame::SimpleError(s) => {
            writer.write_all(b"-").await?;
            writer.write_all(s.as_bytes()).await?;
            writer.write_all(b"\r\n").await?;
        }
        Resp3Frame::Integer(n) => {
            writer.write_all(b":").await?;
            writer.write_all(n.to_string().as_bytes()).await?;
            writer.write_all(b"\r\n").await?;
        }
        Resp3Frame::BulkString(data) => {
            writer.write_all(b"$").await?;
            writer.write_all(data.len().to_string().as_bytes()).await?;
            writer.write_all(b"\r\n").await?;
            writer.write_all(data).await?;
            writer.write_all(b"\r\n").await?;
        }
        Resp3Frame::Array(frames) => {
            writer.write_all(b"*").await?;
            writer
                .write_all(frames.len().to_string().as_bytes())
                .await?;
            writer.write_all(b"\r\n").await?;
            for f in frames {
                Box::pin(write_frame(writer, f)).await?;
            }
        }
        Resp3Frame::Map(pairs) => {
            writer.write_all(b"%").await?;
            writer.write_all(pairs.len().to_string().as_bytes()).await?;
            writer.write_all(b"\r\n").await?;
            for (k, v) in pairs {
                Box::pin(write_frame(writer, k)).await?;
                Box::pin(write_frame(writer, v)).await?;
            }
        }
        Resp3Frame::Null => {
            writer.write_all(b"_\r\n").await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp3::reader::read_frame;
    use std::io::Cursor;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn write_read_roundtrip() {
        let frames = vec![
            Resp3Frame::SimpleString("OK".into()),
            Resp3Frame::SimpleError("ERR oops".into()),
            Resp3Frame::Integer(-7),
            Resp3Frame::BulkString(b"hello world".to_vec()),
            Resp3Frame::Array(vec![
                Resp3Frame::BulkString(b"GET".to_vec()),
                Resp3Frame::BulkString(b"key".to_vec()),
            ]),
            Resp3Frame::Null,
            Resp3Frame::Map(vec![(
                Resp3Frame::BulkString(b"status".to_vec()),
                Resp3Frame::SimpleString("OK".into()),
            )]),
        ];

        for original in &frames {
            let mut buf = Vec::new();
            write_frame(&mut buf, original).await.unwrap();

            let mut reader = BufReader::new(Cursor::new(buf));
            let parsed = read_frame(&mut reader).await.unwrap().unwrap();
            assert_eq!(&parsed, original);
        }
    }
}
