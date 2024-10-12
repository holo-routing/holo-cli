//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_yang as yang;
use proto::northbound_client::NorthboundClient;
use yang3::data::{
    Data, DataDiffFlags, DataFormat, DataPrinterFlags, DataTree,
};

use crate::client::{Client, DataType, DataValue};
use crate::error::Error;

pub mod proto {
    tonic::include_proto!("holo");
}

type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

// The order of the fields in this struct is important. They must be ordered
// such that when `Client` is dropped the client is dropped before the runtime.
// Not doing this will result in a deadlock when dropped. Rust drops struct
// fields in declaration order.
#[derive(Debug)]
pub struct GrpcClient {
    client: NorthboundClient<tonic::transport::Channel>,
    runtime: tokio::runtime::Runtime,
}

// ===== impl GrpcClient =====

impl GrpcClient {
    fn rpc_sync_capabilities(
        &mut self,
    ) -> Result<tonic::Response<proto::CapabilitiesResponse>, tonic::Status>
    {
        let request = tonic::Request::new(proto::CapabilitiesRequest {});
        self.runtime.block_on(self.client.capabilities(request))
    }

    fn rpc_sync_get(
        &mut self,
        request: proto::GetRequest,
    ) -> Result<tonic::Response<proto::GetResponse>, tonic::Status> {
        let request = tonic::Request::new(request);
        self.runtime.block_on(self.client.get(request))
    }

    fn rpc_sync_commit(
        &mut self,
        request: proto::CommitRequest,
    ) -> Result<tonic::Response<proto::CommitResponse>, tonic::Status> {
        let request = tonic::Request::new(request);
        self.runtime.block_on(self.client.commit(request))
    }

    fn rpc_sync_validate(
        &mut self,
        request: proto::ValidateRequest,
    ) -> Result<tonic::Response<proto::ValidateResponse>, tonic::Status> {
        let request = tonic::Request::new(request);
        self.runtime.block_on(self.client.validate(request))
    }
}

impl Client for GrpcClient {
    fn connect(dest: &'static str) -> Result<Self, StdError> {
        // Initialize tokio runtime.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to obtain a new runtime object");

        // Connect to holod.
        let client = runtime
            .block_on(NorthboundClient::connect(dest))?
            .max_encoding_message_size(usize::MAX)
            .max_decoding_message_size(usize::MAX);

        Ok(GrpcClient { client, runtime })
    }

    fn load_modules(&mut self, yang_ctx: &mut yang3::context::Context) {
        // Retrieve the set of capabilities supported by the daemon.
        let capabilities = self
            .rpc_sync_capabilities()
            .expect("Failed to parse gRPC Capabilities() response");

        // Load YANG modules dynamically.
        for module in capabilities.into_inner().supported_modules {
            yang::load_module(yang_ctx, &module.name);
        }
    }

    fn get(
        &mut self,
        data_type: DataType,
        format: DataFormat,
        with_defaults: bool,
        xpath: Option<String>,
    ) -> Result<DataValue, Error> {
        let data = self
            .rpc_sync_get(proto::GetRequest {
                r#type: proto::get_request::DataType::from(data_type) as i32,
                encoding: proto::Encoding::from(format) as i32,
                with_defaults,
                path: xpath.unwrap_or_default(),
            })
            .map_err(Error::Backend)?
            .into_inner()
            .data
            .unwrap();
        let data = match data.data.unwrap() {
            proto::data_tree::Data::DataString(string) => {
                DataValue::String(string)
            }
            proto::data_tree::Data::DataBytes(bytes) => {
                DataValue::Binary(bytes)
            }
        };
        Ok(data)
    }

    fn validate_candidate(
        &mut self,
        candidate: &DataTree<'static>,
    ) -> Result<(), Error> {
        let config = {
            let encoding = proto::Encoding::Lyb as i32;
            let bytes = candidate
                .print_bytes(DataFormat::LYB, DataPrinterFlags::WITH_SIBLINGS)
                .expect("Failed to encode data tree");

            Some(proto::DataTree {
                encoding,
                data: Some(proto::data_tree::Data::DataBytes(bytes)),
            })
        };

        self.rpc_sync_validate(proto::ValidateRequest { config })
            .map_err(Error::Backend)?;

        Ok(())
    }

    fn commit_candidate(
        &mut self,
        running: &DataTree<'static>,
        candidate: &DataTree<'static>,
        comment: Option<String>,
    ) -> Result<(), Error> {
        let operation = proto::commit_request::Operation::Change as i32;
        let config = {
            let encoding = proto::Encoding::Lyb as i32;
            let diff = running
                .diff(candidate, DataDiffFlags::DEFAULTS)
                .expect("Failed to compare configurations");
            let bytes = diff
                .print_bytes(DataFormat::LYB, DataPrinterFlags::WITH_SIBLINGS)
                .expect("Failed to encode data diff");

            Some(proto::DataTree {
                encoding,
                data: Some(proto::data_tree::Data::DataBytes(bytes)),
            })
        };

        self.rpc_sync_commit(proto::CommitRequest {
            operation,
            config,
            comment: comment.unwrap_or_default(),
            confirmed_timeout: 0,
        })
        .map_err(Error::Backend)?;

        Ok(())
    }
}

// ===== From/TryFrom conversion methods =====

impl From<DataType> for proto::get_request::DataType {
    fn from(data_type: DataType) -> proto::get_request::DataType {
        match data_type {
            DataType::All => proto::get_request::DataType::All,
            DataType::Config => proto::get_request::DataType::Config,
            DataType::State => proto::get_request::DataType::State,
        }
    }
}

impl From<DataFormat> for proto::Encoding {
    fn from(format: DataFormat) -> proto::Encoding {
        match format {
            DataFormat::JSON => proto::Encoding::Json,
            DataFormat::XML => proto::Encoding::Xml,
            DataFormat::LYB => proto::Encoding::Lyb,
        }
    }
}
