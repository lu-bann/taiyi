use alloy_rpc_types_beacon::events::HeadEvent;
use bytes::Bytes;
use futures::{pin_mut, Stream, StreamExt};
use reqwest::{Client, Error};

const EVENT_KEY: &str = "event:head";

pub async fn get_event_stream(
    url: &str,
) -> Result<impl Stream<Item = Result<Bytes, Error>>, reqwest::Error> {
    let client = Client::new();
    let response = client
        .get(format!("{url}/eth/v1/events?topics=head"))
        .header("Accept", "text/event-stream")
        .send()
        .await?;
    Ok(response.bytes_stream())
}

pub async fn process_event_stream<F: Fn(HeadEvent)>(
    stream: impl Stream<Item = Result<Bytes, Error>>,
    f: F,
) -> Result<(), std::io::Error> {
    pin_mut!(stream);
    while let Some(Ok(bytes)) = stream.next().await {
        let text = String::from_utf8_lossy(&bytes);
        if text.contains(EVENT_KEY) {
            let text =
                text.trim().trim_start_matches(EVENT_KEY).trim().trim_start_matches("data:").trim();
            let head: HeadEvent = serde_json::from_str(text)?;
            f(head);
        }
    }
    Ok(())
}
