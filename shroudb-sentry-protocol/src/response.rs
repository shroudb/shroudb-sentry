use crate::CommandError;

/// Command execution result.
#[derive(Debug)]
pub enum CommandResponse {
    Success(ResponseMap),
    Error(CommandError),
    Array(Vec<CommandResponse>),
}

/// A map of string keys to response values.
/// Every success response has at least a `status` key.
#[derive(Clone, Debug)]
pub struct ResponseMap {
    pub fields: Vec<(String, ResponseValue)>,
}

impl ResponseMap {
    pub fn ok() -> Self {
        Self {
            fields: vec![("status".into(), ResponseValue::String("OK".into()))],
        }
    }

    pub fn with(mut self, key: impl Into<String>, value: ResponseValue) -> Self {
        self.fields.push((key.into(), value));
        self
    }
}

/// Response value types that map to RESP3 wire frames.
#[derive(Clone, Debug)]
pub enum ResponseValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Null,
    Map(ResponseMap),
    Array(Vec<ResponseValue>),
}
