use std::sync::Arc;

use alloy_primitives::{hex, keccak256};
use futures_util::StreamExt;
use redb::Database;
use reqwest::Url;
use reqwest_eventsource::{Event, EventSource};
use taiyi_primitives::{PreconfRequest, PreconfResponseData};
use tracing::{debug, error};

use crate::{
    preconf_request_data::PreconfRequestData,
    table_definitions::{PRECONF_DATA_TABLE, PRECONF_TABLE},
};

pub async fn handle_underwriter_stream(preconf_db: Arc<Database>, url: Url) -> eyre::Result<()> {
    let req = reqwest::Client::new().get(url);

    let mut event_source = match EventSource::new(req) {
        Ok(source) => source,
        Err(err) => {
            error!("Failed to create EventSource: {:?}", err);
            return Ok(());
        }
    };

    while let Some(event) = event_source.next().await {
        match event {
            Ok(Event::Message(message)) => {
                let data = &message.data;

                let parsed_data = match serde_json::from_str::<
                    Vec<(PreconfRequest, PreconfResponseData)>,
                >(data)
                {
                    Ok(data) => data,
                    Err(e) => {
                        error!("Failed to parse preconf data: {}", e);
                        continue;
                    }
                };

                debug!("[Stream Ingestor]: Received {} preconfirmations", parsed_data.len());

                for (preconf_request, preconf_response_data) in parsed_data.iter() {
                    let target_slot = preconf_request.target_slot();
                    debug!(
                        "[Stream Ingestor]: Processing preconfirmation for slot {}",
                        target_slot
                    );

                    let commitment = match &preconf_response_data.commitment {
                        Some(c) => c,
                        None => {
                            error!("Missing commitment for slot {}", target_slot);
                            continue;
                        }
                    };

                    let preconf_request_data = PreconfRequestData {
                        preconf_type: match preconf_request {
                            PreconfRequest::TypeA(_) => 0,
                            PreconfRequest::TypeB(_) => 1,
                        },
                        preconf_request: match preconf_request {
                            PreconfRequest::TypeA(preconf_request) => {
                                match serde_json::to_string(preconf_request) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to serialize TypeA request: {}", e);
                                        continue;
                                    }
                                }
                            }
                            PreconfRequest::TypeB(preconf_request) => {
                                match serde_json::to_string(preconf_request) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to serialize TypeB request: {}", e);
                                        continue;
                                    }
                                }
                            }
                        },
                        preconf_request_signature: hex::encode(commitment.as_bytes()),
                    };

                    let challenge_id = keccak256(commitment.as_bytes()).to_string();

                    let write_tx = match preconf_db.begin_write() {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("Failed to begin write transaction: {}", e);
                            continue;
                        }
                    };

                    {
                        let mut table = match write_tx.open_table(PRECONF_DATA_TABLE) {
                            Ok(t) => t,
                            Err(e) => {
                                error!("Failed to open PRECONF_DATA_TABLE: {}", e);
                                continue;
                            }
                        };

                        if let Err(e) = table.insert(&challenge_id, preconf_request_data) {
                            error!("Failed to insert preconf data: {}", e);
                            continue;
                        };
                    }

                    if let Err(e) = write_tx.commit() {
                        error!("Failed to commit write transaction: {}", e);
                        continue;
                    }

                    let read_tx = match preconf_db.begin_read() {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("Failed to begin read transaction: {}", e);
                            continue;
                        }
                    };

                    let table = match read_tx.open_table(PRECONF_TABLE) {
                        Ok(t) => t,
                        Err(e) => {
                            error!("Failed to open PRECONF_TABLE: {}", e);
                            continue;
                        }
                    };

                    let preconfs = match table.get(&target_slot) {
                        Ok(Some(p)) => p.value(),
                        Ok(None) => Vec::new(),
                        Err(e) => {
                            error!("Failed to get preconfs: {}", e);
                            continue;
                        }
                    };

                    let mut preconfs = preconfs;
                    preconfs.push(challenge_id.clone());

                    let write_tx = match preconf_db.begin_write() {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("Failed to begin write transaction: {}", e);
                            continue;
                        }
                    };

                    {
                        let mut table = match write_tx.open_table(PRECONF_TABLE) {
                            Ok(t) => t,
                            Err(e) => {
                                error!("Failed to open PRECONF_TABLE: {}", e);
                                continue;
                            }
                        };

                        if let Err(e) = table.insert(&target_slot, preconfs) {
                            error!("Failed to insert preconfs: {}", e);
                            continue;
                        };
                    }

                    if let Err(e) = write_tx.commit() {
                        error!("Failed to commit write transaction: {}", e);
                        continue;
                    }

                    debug!(
                        "[Stream Ingestor]: Stored preconfirmation for slot {} with challenge id {}",
                        target_slot, challenge_id
                    );
                }
            }
            Ok(Event::Open) => {
                debug!("[Stream Ingestor]: SSE connection opened");
            }
            Err(err) => {
                error!("[Stream Ingestor]: Error receiving SSE event: {:?}", err);
            }
        }
    }

    Ok(())
}
