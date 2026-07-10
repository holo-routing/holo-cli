//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::grpc::proto;
use crate::grpc::proto::northbound_client::NorthboundClient;

// Maximum number of notifications retained in the circular buffer.
pub const NOTIFICATION_BUFFER_SIZE: usize = 1024;

#[derive(Debug)]
pub struct NotificationEntry {
    // Timestamp in seconds since Epoch.
    pub timestamp: i64,
    // The YANG notification data path.
    pub module_path: String,
    // The notification data, JSON-encoded.
    pub data_json: String,
}

#[derive(Debug, Default)]
pub struct NotificationBuffer {
    entries: VecDeque<NotificationEntry>,
    // Reason the receiver stopped on its own, if it did.
    status: Option<String>,
}

// ===== impl NotificationBuffer =====

impl NotificationBuffer {
    pub fn push(&mut self, entry: NotificationEntry) {
        if self.entries.len() == NOTIFICATION_BUFFER_SIZE {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    pub fn entries(&self) -> impl Iterator<Item = &NotificationEntry> {
        self.entries.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    pub fn set_status(&mut self, status: Option<String>) {
        self.status = status;
    }
}

#[derive(Debug)]
pub struct Subscription {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    handle: std::thread::JoinHandle<()>,
}

// ===== impl Subscription =====

impl Subscription {
    // Connects to holod, subscribes to all notifications and spawns a
    // background thread that pushes received notifications into the given
    // buffer.
    pub fn start(
        addr: &'static str,
        buffer: Arc<Mutex<NotificationBuffer>>,
    ) -> Result<Subscription, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("failed to create runtime: {}", error))?;

        // Connect and subscribe synchronously so failures are reported
        // immediately, before any thread is spawned.
        let (client, stream) = runtime.block_on(async {
            let mut client = NorthboundClient::connect(addr)
                .await
                .map_err(|error| {
                    format!("connection to holod failed: {}", error)
                })?
                .max_decoding_message_size(usize::MAX);
            let stream = client
                .subscribe(proto::SubscribeRequest {
                    encoding: proto::Encoding::Json as i32,
                    path: String::new(),
                })
                .await
                .map_err(|error| {
                    format!("subscribe request failed: {}", error)
                })?
                .into_inner();
            Ok::<_, String>((client, stream))
        })?;

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let handle = std::thread::spawn(move || {
            // The client and the stream must be dropped before the runtime
            // to avoid a deadlock (see the comment on `GrpcClient`), hence
            // both are moved into the async block driven by `block_on`.
            runtime.block_on(async move {
                let _client = client;
                let mut stream = stream;
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        message = stream.message() => {
                            let mut buffer = buffer
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            match message {
                                Ok(Some(notification)) => {
                                    buffer.push(notification.into());
                                }
                                Ok(None) => {
                                    buffer.set_status(Some(
                                        "stream closed by server".to_owned(),
                                    ));
                                    break;
                                }
                                Err(error) => {
                                    buffer.set_status(Some(format!(
                                        "stream error: {}",
                                        error
                                    )));
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        });

        Ok(Subscription {
            shutdown_tx,
            handle,
        })
    }

    // Returns whether the receiver thread has terminated on its own.
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    // Signals the receiver thread to stop and waits for it to finish.
    pub fn stop(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.handle.join();
    }
}

// ===== impl NotificationEntry =====

impl From<proto::Notification> for NotificationEntry {
    fn from(notification: proto::Notification) -> NotificationEntry {
        let data_json = match notification.data.and_then(|data| data.data) {
            Some(proto::data_tree::Data::DataString(string)) => string,
            _ => "<no data>".to_owned(),
        };
        NotificationEntry {
            timestamp: notification.timestamp,
            module_path: notification.module_path,
            data_json,
        }
    }
}
