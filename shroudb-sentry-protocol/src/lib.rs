//! Protocol layer for ShrouDB Sentry.
//!
//! Command parsing, dispatch, handler execution, and response serialization.
//! Sentry evaluates authorization policies and returns signed JWT decisions.

pub mod auth;
pub mod command;
pub mod command_parser;
pub mod decision_cache;
pub mod dispatch;
pub mod engine_handler;
pub mod error;
pub mod handlers;
pub mod recovery;
pub mod remote_signer;
pub mod resp3;
pub mod response;
pub mod scheduler;
pub mod serialize;
pub mod signing_index;

pub use command::Command;
pub use dispatch::CommandDispatcher;
pub use error::CommandError;
pub use resp3::Resp3Frame;
pub use response::{CommandResponse, ResponseMap, ResponseValue};
