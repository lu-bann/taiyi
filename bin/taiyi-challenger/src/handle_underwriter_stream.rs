use std::sync::Arc;

use alloy_primitives::hex;
use futures_util::StreamExt;
use redb::Database;
use reqwest::Url;
use reqwest_eventsource::{Event, EventSource};
use taiyi_primitives::{PreconfRequest, PreconfResponseData};
use tracing::{debug, error};

use crate::{preconf_request_data::PreconfRequestData, table_definitions::PRECONF_TABLE};

pub async fn handle_underwriter_stream(preconf_db: Arc<Database>, url: Url) -> eyre::Result<()> {
    let req = reqwest::Client::new().get(url);

    let mut event_source = EventSource::new(req)?;
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
                        error!("[Stream Ingestor]: Failed to parse preconf data: {}", e);
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

                    let preconf_request_data = PreconfRequestData {
                        preconf_type: match preconf_request {
                            PreconfRequest::TypeA(_) => 0,
                            PreconfRequest::TypeB(_) => 1,
                        },
                        preconf_request: match preconf_request {
                            PreconfRequest::TypeA(preconf_request) => {
                                match serde_json::to_string(&preconf_request) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("[Stream Ingestor]: Failed to serialize preconf request: {}", e);
                                        continue;
                                    }
                                }
                            }
                            PreconfRequest::TypeB(preconf_request) => {
                                match serde_json::to_string(&preconf_request) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("[Stream Ingestor]: Failed to serialize preconf request: {}", e);
                                        continue;
                                    }
                                }
                            }
                        },
                        preconf_request_signature: match &preconf_response_data.commitment {
                            Some(commitment) => hex::encode(commitment.as_bytes()),
                            None => {
                                error!("[Stream Ingestor]: Missing commitment in preconf response");
                                continue;
                            }
                        },
                    };

                    let read_tx = match preconf_db.begin_read() {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("[Stream Ingestor]: Failed to begin read transaction: {}", e);
                            continue;
                        }
                    };

                    let table = match read_tx.open_table(PRECONF_TABLE) {
                        Ok(table) => table,
                        Err(e) => {
                            error!("[Stream Ingestor]: Failed to open preconf table: {}", e);
                            continue;
                        }
                    };

                    let mut preconf_values = match table.get(&target_slot) {
                        Ok(Some(val)) => val.value(),
                        Ok(None) => Vec::new(),
                        Err(e) => {
                            error!(
                                "[Stream Ingestor]: Storage error for slot {}: {}",
                                target_slot, e
                            );
                            continue;
                        }
                    };

                    preconf_values.push(preconf_request_data);

                    let write_result = (|| -> Result<(), redb::Error> {
                        let write_tx = preconf_db.begin_write()?;
                        {
                            let mut table = write_tx.open_table(PRECONF_TABLE)?;
                            table.insert(&target_slot, preconf_values)?;
                        }
                        write_tx.commit()?;
                        Ok(())
                    })();

                    if let Err(e) = write_result {
                        error!("[Stream Ingestor]: Failed to write preconf data: {}", e);
                        continue;
                    }

                    debug!("[Stream Ingestor]: Stored preconfirmation for slot {}", target_slot);
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
