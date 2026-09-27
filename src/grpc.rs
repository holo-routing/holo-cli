//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

use hyper_util::rt::TokioIo;
use proto::northbound_client::NorthboundClient;
use tokio::net::UnixStream;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use yang5::data::{
    Data, DataDiffFlags, DataFormat, DataParserFlags, DataPrinterFlags,
    DataTree, DataValidationFlags,
};
use yang5::ffi;

use crate::error::Error;
use crate::{YANG_CTX, YANG_MODULES_DIR};

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
    client: NorthboundClient<InterceptedService<Channel, Credentials>>,
    runtime: tokio::runtime::Runtime,
    credentials: Credentials,
}

// Credentials sent to the daemon with every request.
//
// Both are absent when the daemon has no users configured.
#[derive(Clone, Debug, Default)]
pub struct Credentials {
    username: Option<MetadataValue<Ascii>>,
    password: Option<MetadataValue<Ascii>>,
}

// ===== impl Credentials =====

impl Credentials {
    pub fn new(
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Credentials, StdError> {
        Ok(Credentials {
            username: username
                .map(MetadataValue::<Ascii>::try_from)
                .transpose()?,
            password: password
                .map(MetadataValue::<Ascii>::try_from)
                .transpose()?,
        })
    }
}

impl Interceptor for Credentials {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(username) = &self.username {
            request.metadata_mut().insert("username", username.clone());
        }
        if let Some(password) = &self.password {
            request.metadata_mut().insert("password", password.clone());
        }

        Ok(request)
    }
}

// ===== impl GrpcClient =====

impl GrpcClient {
    pub fn connect(
        dest: &'static str,
        credentials: Credentials,
    ) -> Result<Self, StdError> {
        // Initialize tokio runtime.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to obtain a new runtime object");

        // Connect to holod, over a Unix socket when the destination is a path.
        let channel = match dest.starts_with('/') {
            true => runtime.block_on(
                // The URI is required by the endpoint builder but goes unused,
                // since the connector below decides where to connect.
                Endpoint::try_from("http://[::]:50051")?
                    .connect_with_connector(service_fn(
                        move |_: Uri| async move {
                            let stream = UnixStream::connect(dest).await?;
                            Ok::<_, std::io::Error>(TokioIo::new(stream))
                        },
                    )),
            )?,
            false => runtime.block_on(Endpoint::try_from(dest)?.connect())?,
        };
        let client =
            NorthboundClient::with_interceptor(channel, credentials.clone())
                .max_encoding_message_size(usize::MAX)
                .max_decoding_message_size(usize::MAX);

        Ok(GrpcClient {
            client,
            runtime,
            credentials,
        })
    }

    pub fn load_modules(
        &mut self,
        dest: &'static str,
        yang_ctx: &mut yang5::context::Context,
    ) {
        // Retrieve the set of capabilities supported by the daemon.
        let capabilities = self
            .rpc_sync_capabilities()
            .expect("Failed to parse gRPC Capabilities() response");

        // Establish a separate connection to holod for libyang to fetch any
        // missing YANG modules or submodules using the `GetSchema` RPC.
        let client = Self::connect(dest, self.credentials.clone())
            .expect("Connection to holod failed");
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

    pub fn get_config(
        &mut self,
        with_defaults: bool,
        xpath: Option<String>,
    ) -> Result<DataTree<'static>, Error> {
        let path = xpath.map(|x| proto::Path::from_xpath(&x));
        let response = self
            .rpc_sync_get_config(proto::GetConfigRequest {
                encoding: proto::Encoding::Lyb as i32,
                with_defaults,
                path,
            })
            .map_err(Error::Backend)?
            .into_inner();
        data_tree_parse(
            response.data.as_ref(),
            DataParserFlags::NO_VALIDATION,
            DataValidationFlags::PRESENT | DataValidationFlags::NO_STATE,
        )
    }

    pub fn get_state(
        &mut self,
        with_defaults: bool,
        xpath: Option<String>,
    ) -> Result<DataTree<'static>, Error> {
        let path = xpath.map(|x| proto::Path::from_xpath(&x));
        let response = self
            .rpc_sync_get_state(proto::GetStateRequest {
                encoding: proto::Encoding::Lyb as i32,
                with_defaults,
                path,
            })
            .map_err(Error::Backend)?
            .into_inner();
        data_tree_parse(
            response.data.as_ref(),
            DataParserFlags::NO_VALIDATION,
            DataValidationFlags::PRESENT,
        )
    }

    pub fn validate_candidate(
        &mut self,
        candidate: &DataTree<'static>,
    ) -> Result<(), Error> {
        let config = proto::DataTree::new(DataFormat::LYB, candidate);
        self.rpc_sync_validate(proto::ValidateRequest {
            config: Some(config),
        })
        .map_err(Error::Backend)?;

        Ok(())
    }

    pub fn commit_candidate(
        &mut self,
        running: &DataTree<'static>,
        candidate: &DataTree<'static>,
        comment: Option<String>,
    ) -> Result<(), Error> {
        let operation = proto::commit_request::Operation::Change as i32;
        let diff = running
            .diff(candidate, DataDiffFlags::DEFAULTS)
            .expect("Failed to compare configurations");
        let config = proto::DataTree::new(DataFormat::LYB, &diff);
        self.rpc_sync_commit(proto::CommitRequest {
            operation,
            config: Some(config),
            comment: comment.unwrap_or_default(),
            confirmed_timeout: 0,
        })
        .map_err(Error::Backend)?;

        Ok(())
    }

    pub fn execute(
        &mut self,
        data: DataTree<'static>,
    ) -> Result<proto::data_tree::Data, Error> {
        let data = self
            .rpc_sync_execute(proto::ExecuteRequest {
                data: Some(proto::DataTree::new(DataFormat::LYB, &data)),
            })
            .map_err(Error::Backend)?
            .into_inner()
            .data
            .unwrap();
        Ok(data.data.unwrap())
    }

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

    fn rpc_sync_get_config(
        &mut self,
        request: proto::GetConfigRequest,
    ) -> Result<tonic::Response<proto::GetConfigResponse>, tonic::Status> {
        let request = tonic::Request::new(request);
        self.runtime.block_on(self.client.get_config(request))
    }

    fn rpc_sync_get_state(
        &mut self,
        request: proto::GetStateRequest,
    ) -> Result<tonic::Response<proto::GetStateResponse>, tonic::Status> {
        let request = tonic::Request::new(request);
        self.runtime.block_on(self.client.get_state(request))
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

    fn rpc_sync_execute(
        &mut self,
        request: proto::ExecuteRequest,
    ) -> Result<tonic::Response<proto::ExecuteResponse>, tonic::Status> {
        let request = tonic::Request::new(request);
        self.runtime.block_on(self.client.execute(request))
    }
}

// ===== impl proto::DataTree =====

impl proto::DataTree {
    fn new<'a>(format: DataFormat, data: &impl Data<'a>) -> Self {
        let encoding = proto::Encoding::from(format) as i32;
        let data = match format {
            DataFormat::JSON | DataFormat::XML => {
                let string = data
                    .print_string(format, DataPrinterFlags::WITH_SIBLINGS)
                    .expect("Failed to encode data tree");
                proto::data_tree::Data::DataString(string)
            }
            DataFormat::LYB => {
                let bytes = data
                    .print_bytes(format, DataPrinterFlags::WITH_SIBLINGS)
                    .expect("Failed to encode data tree");
                proto::data_tree::Data::DataBytes(bytes)
            }
        };
        proto::DataTree {
            encoding,
            data: Some(data),
        }
    }
}

// ===== impl proto::Path =====

impl proto::Path {
    pub fn from_xpath(xpath: &str) -> Self {
        let elems = xpath
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|segment| {
                let (name, keys) = match segment.find('[') {
                    Some(pos) => {
                        let name = &segment[..pos];
                        let mut keys = HashMap::new();
                        for kv in segment[pos..].split('[').filter(|s| !s.is_empty())
                        {
                            let kv = kv.trim_end_matches(']');
                            if let Some(eq_pos) = kv.find('=') {
                                let key = kv[..eq_pos].to_owned();
                                let value = kv[eq_pos + 1..]
                                    .trim_matches('\'')
                                    .to_owned();
                                keys.insert(key, value);
                            }
                        }
                        (name, keys)
                    }
                    None => (segment, HashMap::new()),
                };
                proto::PathElem {
                    name: name.to_owned(),
                    key: keys,
                }
            })
            .collect();
        proto::Path { elem: elems }
    }
}

// ===== From/TryFrom conversion methods =====

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

// Parses a data tree received from the daemon in the LYB format.
fn data_tree_parse(
    data_tree: Option<&proto::DataTree>,
    parser_flags: DataParserFlags,
    validation_flags: DataValidationFlags,
) -> Result<DataTree<'static>, Error> {
    let yang_ctx = YANG_CTX.get().unwrap();
    let data = match data_tree.and_then(|data_tree| data_tree.data.as_ref()) {
        Some(proto::data_tree::Data::DataBytes(data)) => data.as_slice(),
        Some(proto::data_tree::Data::DataString(data)) => data.as_bytes(),
        None => return Ok(DataTree::new(yang_ctx)),
    };
    DataTree::parse_string(
        yang_ctx,
        data,
        DataFormat::LYB,
        parser_flags,
        validation_flags,
    )
    .map_err(Error::Data)
}

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
