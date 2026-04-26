//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use indextree::NodeId;

use crate::pipe::PipeError;

#[derive(Debug)]
pub enum Error {
    Parser(ParserError),
    EditConfig(yang5::Error),
    ValidateConfig(yang5::Error),
    Callback(CallbackError),
    Backend(tonic::Status),
    Pipe(PipeError),
}

#[derive(Debug)]
pub enum ParserError {
    NoMatch(String),
    Incomplete(NodeId),
    Ambiguous(Vec<NodeId>),
}

#[derive(Debug)]
pub enum CallbackError {
    BrokenPipe,
    Other(String),
}

// ===== impl Error =====

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parser(error) => write!(f, "{}", error),
            Error::EditConfig(error) => {
                write!(f, "failed to edit configuration: {}", error)
            }
            Error::ValidateConfig(error) => {
                write!(f, "failed to validate configuration: {}", error)
            }
            Error::Callback(error) => {
                write!(f, "failed to execute command: {}", error)
            }
            Error::Backend(error) => {
                write!(f, "{}", error)
            }
            Error::Pipe(error) => {
                write!(f, "{}", error)
            }
        }
    }
}

impl std::error::Error for Error {}

// ===== impl ParserError =====

impl std::fmt::Display for ParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParserError::NoMatch(command) => {
                write!(f, "unknown command: {}", command)
            }
            ParserError::Incomplete(_) => write!(f, "incomplete command"),
            ParserError::Ambiguous(_) => write!(f, "ambiguous command"),
        }
    }
}

impl std::error::Error for ParserError {}

// ===== impl CallbackError =====

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallbackError::BrokenPipe => write!(f, "broken pipe"),
            CallbackError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<String> for CallbackError {
    fn from(s: String) -> Self {
        CallbackError::Other(s)
    }
}

impl From<std::io::Error> for CallbackError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            CallbackError::BrokenPipe
        } else {
            CallbackError::Other(e.to_string())
        }
    }
}
