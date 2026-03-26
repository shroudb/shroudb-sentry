//! Bridge RESP3 frames to Sentry commands.
//!
//! Extracts bulk strings from a RESP3 array frame and delegates to
//! the command parser.

use crate::command::Command;
use crate::command_parser;
use crate::error::CommandError;

use super::Resp3Frame;

/// Convert a RESP3 frame (an array of bulk strings) into a Sentry `Command`.
pub fn parse_command(frame: Resp3Frame) -> Result<Command, CommandError> {
    let parts = match frame {
        Resp3Frame::Array(parts) => parts,
        _ => {
            return Err(CommandError::BadArg {
                message: "expected array frame".into(),
            });
        }
    };

    let strings: Vec<String> = parts
        .into_iter()
        .map(frame_to_string)
        .collect::<Result<_, _>>()?;

    command_parser::parse_command(strings)
}

fn frame_to_string(frame: Resp3Frame) -> Result<String, CommandError> {
    match frame {
        Resp3Frame::BulkString(bytes) => {
            String::from_utf8(bytes).map_err(|_| CommandError::BadArg {
                message: "non-UTF-8 bulk string".into(),
            })
        }
        Resp3Frame::SimpleString(s) => Ok(s),
        Resp3Frame::Integer(n) => Ok(n.to_string()),
        _ => Err(CommandError::BadArg {
            message: "unexpected frame type in command".into(),
        }),
    }
}
