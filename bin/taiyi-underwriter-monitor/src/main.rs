use alloy_primitives::hex;
use futures_util::StreamExt as _;
use reqwest::Url;
use reqwest_eventsource::{Event, EventSource};
use sqlx::{types::BigDecimal, Pool, Postgres};
use taiyi_primitives::{PreconfRequest, PreconfResponseData};
use tracing::{debug, error};

type TaiyiDBConnection = Pool<Postgres>;

async fn handle_underwriter_stream(db_conn: TaiyiDBConnection, url: Url) -> eyre::Result<()> {
    let req = reqwest::Client::new().get(url);

    let mut event_source = EventSource::new(req).unwrap_or_else(|err| {
        panic!("Failed to create EventSource: {:?}", err);
    });

    while let Some(event) = event_source.next().await {
        match event {
            Ok(Event::Message(message)) => {
                let data = &message.data;

                let parsed_data =
                    serde_json::from_str::<Vec<(PreconfRequest, PreconfResponseData)>>(data)
                        .unwrap();

                debug!("[Stream Ingestor]: Received {} preconfirmations", parsed_data.len());

                for (preconf_request, preconf_response_data) in parsed_data.iter() {
                    let target_slot = preconf_request.target_slot();
                    debug!(
                        "[Stream Ingestor]: Processing preconfirmation for slot {}",
                        target_slot
                    );
                    // TODO store relevant info into DB
                    let _ = match preconf_request {
                        PreconfRequest::TypeA(preconf_request_type_a) => {
                            todo!()
                        }
                        PreconfRequest::TypeB(preconf_request_type_b) => {
                            let hash =
                                preconf_request_type_b.transaction.as_ref().unwrap().tx_hash();

                            hash
                        }
                    };
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

fn main() {}
