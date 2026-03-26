use crate::response::{CommandResponse, ResponseMap, ResponseValue};

use crate::resp3::Resp3Frame;

/// Convert a `CommandResponse` into a RESP3 frame for wire serialization.
pub fn response_to_frame(response: &CommandResponse) -> Resp3Frame {
    match response {
        CommandResponse::Success(map) => response_map_to_frame(map),
        CommandResponse::Error(err) => {
            Resp3Frame::SimpleError(format!("{} {}", err.error_code(), err))
        }
        CommandResponse::Array(items) => {
            Resp3Frame::Array(items.iter().map(response_to_frame).collect())
        }
    }
}

fn response_map_to_frame(map: &ResponseMap) -> Resp3Frame {
    Resp3Frame::Map(
        map.fields
            .iter()
            .map(|(k, v)| {
                (
                    Resp3Frame::BulkString(k.as_bytes().to_vec()),
                    response_value_to_frame(v),
                )
            })
            .collect(),
    )
}

fn response_value_to_frame(value: &ResponseValue) -> Resp3Frame {
    match value {
        ResponseValue::String(s) => Resp3Frame::BulkString(s.as_bytes().to_vec()),
        ResponseValue::Integer(n) => Resp3Frame::Integer(*n),
        ResponseValue::Boolean(b) => Resp3Frame::BulkString(if *b {
            b"true".to_vec()
        } else {
            b"false".to_vec()
        }),
        ResponseValue::Null => Resp3Frame::Null,
        ResponseValue::Map(map) => response_map_to_frame(map),
        ResponseValue::Array(items) => {
            Resp3Frame::Array(items.iter().map(response_value_to_frame).collect())
        }
    }
}
