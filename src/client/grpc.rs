//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

use proto::northbound_client::NorthboundClient;
use yang3::data::{
    Data, DataDiffFlags, DataFormat, DataPrinterFlags, DataTree,
};
use yang3::ffi;

use crate::client::{Client, DataType, DataValue};
use crate::error::Error;
use crate::YANG_MODULES_DIR;

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

    fn rpc_sync_get_schema(
        &mut self,
        request: proto::GetSchemaRequest,
    ) -> Result<tonic::Response<proto::GetSchemaResponse>, tonic::Status> {
        let request = tonic::Request::new(request);
        self.runtime.block_on(self.client.get_schema(request))
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

    fn load_modules(
        &mut self,
        dest: &'static str,
        yang_ctx: &mut yang3::context::Context,
    ) {
        // Retrieve the set of capabilities supported by the daemon.
        let capabilities = self
            .rpc_sync_capabilities()
            .expect("Failed to parse gRPC Capabilities() response");

        // Establish a separate connection to holod for libyang to fetch any
        // missing YANG modules or submodules using the `GetSchema` RPC.
        let client = Self::connect(dest).expect("Connection to holod failed");
        unsafe {
            yang_ctx.set_module_import_callback(
                ly_module_import_cb,
                Box::into_raw(Box::new(client)) as _,
            )
        };

        // Load YANG modules dynamically.
        for module in capabilities.into_inner().supported_modules {
            let revision = if module.revision.is_empty() {
                None
            } else {
                Some(module.revision.as_ref())
            };
            let features = &module
                .supported_features
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            if let Err(error) =
                yang_ctx.load_module(&module.name, revision, features)
            {
                panic!(
                    "failed to load YANG module ({}): {}",
                    module.name, error
                );
            }
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

// ===== helper functions =====

unsafe extern "C" fn ly_module_import_cb(
    module_name: *const c_char,
    module_revision: *const c_char,
    submodule_name: *const c_char,
    submodule_revision: *const c_char,
    user_data: *mut c_void,
    format: *mut ffi::LYS_INFORMAT::Type,
    module_data: *mut *const c_char,
    _free_module_data: *mut ffi::ly_module_imp_data_free_clb,
) -> ffi::LY_ERR::Type {
    let module_name = char_ptr_to_string(module_name);
    let module_revision = char_ptr_to_opt_string(module_revision);
    let submodule_name = char_ptr_to_opt_string(submodule_name);
    let submodule_revision = char_ptr_to_opt_string(submodule_revision);

    // Retrive module or submodule via gRPC.
    let client = unsafe { &mut *(user_data as *mut GrpcClient) };
    if let Ok(response) = client.rpc_sync_get_schema(proto::GetSchemaRequest {
        module_name: module_name.clone(),
        module_revision: module_revision.clone().unwrap_or_default(),
        submodule_name: submodule_name.clone().unwrap_or_default(),
        submodule_revision: submodule_revision.clone().unwrap_or_default(),
        format: proto::SchemaFormat::Yang.into(),
    }) {
        let data = response.into_inner().data;

        // Cache the module in the filesystem.
        //
        // Exclude Holo augmentation and deviation modules from caching, as they
        // may change without corresponding version updates.
        if !module_name.starts_with("holo") {
            let path =
                match (module_revision, submodule_name, submodule_revision) {
                    (None, None, _) => build_cache_path(&module_name, None),
                    (Some(module_revision), None, _) => {
                        build_cache_path(&module_name, Some(&module_revision))
                    }
                    (_, Some(submodule_name), None) => {
                        build_cache_path(&submodule_name, None)
                    }
                    (_, Some(submodule_name), Some(submodule_revision)) => {
                        build_cache_path(
                            &submodule_name,
                            Some(&submodule_revision),
                        )
                    }
                };
            if let Err(error) = std::fs::write(&path, &data) {
                eprintln!(
                    "Failed to save YANG module in the cache ({}): {}",
                    module_name, error
                );
            }
        }

        // Return the retrieved module or submodule.
        let data = CString::new(data).unwrap();
        unsafe {
            *format = ffi::LYS_INFORMAT::LYS_IN_YANG;
            *module_data = data.as_ptr();
        }
        std::mem::forget(data);
        return ffi::LY_ERR::LY_SUCCESS;
    }

    ffi::LY_ERR::LY_ENOTFOUND
}

// Builds the file path for caching a YANG module or submodule.
fn build_cache_path(name: &str, revision: Option<&str>) -> String {
    match revision {
        Some(revision) => {
            format!("{}/{}@{}.yang", YANG_MODULES_DIR, name, revision)
        }
        None => format!("{}/{}.yang", YANG_MODULES_DIR, name),
    }
}

// Converts C String to owned string.
fn char_ptr_to_string(c_str: *const c_char) -> String {
    unsafe { CStr::from_ptr(c_str).to_string_lossy().into_owned() }
}

// Converts C String to optional owned string.
fn char_ptr_to_opt_string(c_str: *const c_char) -> Option<String> {
    if c_str.is_null() {
        None
    } else {
        Some(char_ptr_to_string(c_str))
    }
}
