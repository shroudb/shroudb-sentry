pub mod parse_command;
pub mod reader;
pub mod writer;

use std::io;

/// A RESP3 protocol frame.
#[derive(Debug, Clone, PartialEq)]
pub enum Resp3Frame {
    SimpleString(String),
    SimpleError(String),
    Integer(i64),
    BulkString(Vec<u8>),
    Array(Vec<Resp3Frame>),
    Map(Vec<(Resp3Frame, Resp3Frame)>),
    Null,
}

/// Errors that occur during RESP3 protocol parsing.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid type byte: 0x{0:02x}")]
    InvalidTypeByte(u8),

    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),

    #[error("nesting too deep")]
    NestingTooDeep,

    #[error("invalid format: {0}")]
    InvalidFormat(String),

    #[error(transparent)]
    Io(#[from] io::Error),
}
