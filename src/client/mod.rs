//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod grpc;

use yang2::data::{DataFormat, DataTree};

use crate::error::Error;

type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub enum DataType {
    All = 0,
    Config = 1,
    State = 2,
}

pub trait Client: Send + std::fmt::Debug {
    // Connect to the Holo daemon.
    fn connect(dest: &'static str) -> Result<Self, StdError>
    where
        Self: Sized;

    // Retrieve and load all supported YANG modules.
    fn load_modules(&mut self, yang_ctx: &mut yang2::context::Context);

    // Retrieve configuration data, state data or both.
    fn get(
        &mut self,
        data_type: DataType,
        format: DataFormat,
        with_defaults: bool,
        xpath: Option<String>,
    ) -> Result<String, Error>;

    // Validate the provided candidate configuration.
    fn validate_candidate(&mut self, candidate: &DataTree)
        -> Result<(), Error>;

    // Commit the provided candidate configuration.
    fn commit_candidate(
        &mut self,
        running: &DataTree,
        candidate: &DataTree,
        comment: Option<String>,
    ) -> Result<(), Error>;
}
