use alloy_rpc_types_beacon::{events::HeadEvent, BlsPublicKey, BlsSignature};
use bytes::Bytes;
use futures::{pin_mut, Stream, StreamExt};
use reqwest::{Client, Error};
use serde::Deserialize;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use taiyi_primitives::slot_info::{SlotInfo, SlotInfoFactory};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

const EVENT_KEY: &str = "event:head";
const DELEGATION_ACTION: u8 = 0;

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

pub trait EventHandler {
    fn handle_event(&self, event: HeadEvent) -> impl Future<Output = Result<(), Error>>;
}

#[derive(Debug, Default)]
pub struct Noop {}

impl Noop {
    pub const fn new() -> Self {
        Self {}
    }
}

impl EventHandler for Noop {
    async fn handle_event(&self, _: HeadEvent) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct StoreLastSlotDecorator<F: EventHandler> {
    last_slot: Arc<AtomicU64>,
    f: F,
}

impl<F: EventHandler> StoreLastSlotDecorator<F> {
    pub const fn new(last_slot: Arc<AtomicU64>, f: F) -> Self {
        Self { last_slot, f }
    }
}

impl<F: EventHandler> EventHandler for StoreLastSlotDecorator<F> {
    async fn handle_event(&self, event: HeadEvent) -> Result<(), Error> {
        let slot = event.slot;
        self.f.handle_event(event).await?;
        self.last_slot.store(slot, Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Debug)]
pub struct StoreAvailableSlotsDecorator<F: EventHandler, Factory: SlotInfoFactory> {
    url: String,
    underwriter: BlsPublicKey,
    available_slots: Arc<RwLock<Vec<SlotInfo>>>,
    slots_per_epoch: u64,
    epoch_lookahead: u64,
    f: F,
    slot_info_factory: Factory,
}

impl<F: EventHandler, Factory: SlotInfoFactory> StoreAvailableSlotsDecorator<F, Factory> {
    pub fn new(
        url: String,
        underwriter: BlsPublicKey,
        available_slots: Arc<RwLock<Vec<SlotInfo>>>,
        slots_per_epoch: u64,
        epoch_lookahead: u64,
        f: F,
        slot_info_factory: Factory,
    ) -> Self {
        Self {
            url,
            underwriter,
            available_slots,
            slots_per_epoch,
            epoch_lookahead,
            f,
            slot_info_factory,
        }
    }

    async fn get_assigned_slots(
        &self,
        first_slot: u64,
        last_slot: u64,
    ) -> Result<Vec<SlotInfo>, Error> {
        let mut assigned_slots = vec![];
        for slot in first_slot..=last_slot {
            if let Some(assigned_validator) = get_assigned_validator(&self.url, slot).await? {
                if assigned_validator == self.underwriter {
                    println!("Delegation to underwriter found for slot: {}", slot);
                    assigned_slots.push(self.slot_info_factory.slot_info(slot));
                }
            }
        }

        Ok(assigned_slots)
    }
}

impl<F: EventHandler, Factory: SlotInfoFactory> EventHandler
    for StoreAvailableSlotsDecorator<F, Factory>
{
    async fn handle_event(&self, event: HeadEvent) -> Result<(), Error> {
        let slot = event.slot;
        let epoch_transition = event.epoch_transition;
        self.f.handle_event(event).await?;
        self.available_slots.write().await.retain(|info| info.slot > slot);
        if epoch_transition {
            let first_slot = slot + self.slots_per_epoch;
            let last_slot = first_slot + self.slots_per_epoch;
            let assigned_slots = self.get_assigned_slots(first_slot, last_slot).await?;
            self.available_slots.write().await.extend(assigned_slots);
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("{0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("{0}")]
    Reqwest(#[from] Error),
}

pub async fn process_event_stream<F: EventHandler>(
    stream: impl Stream<Item = Result<Bytes, Error>>,
    f: F,
) -> Result<(), StreamError> {
    pin_mut!(stream);
    while let Some(Ok(bytes)) = stream.next().await {
        let text = String::from_utf8_lossy(&bytes);
        debug!("begin processing event: {}", text);
        if text.contains(EVENT_KEY) {
            let text =
                text.trim().trim_start_matches(EVENT_KEY).trim().trim_start_matches("data:").trim();
            let head: HeadEvent = serde_json::from_str(text)?;
            match f.handle_event(head).await {
                Ok(_) => debug!("finished processing event: {}", text),
                Err(e) => {
                    error!("error processing event: {e}");
                    continue;
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Hash, PartialEq, Eq)]
pub struct DelegationMessage {
    pub action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Hash, PartialEq, Eq)]
pub struct SignedDelegation {
    pub message: DelegationMessage,
    pub signature: BlsSignature,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct BeaconBlock {
    version: String,
    data: BeaconBlockData,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct BeaconBlockData {
    message: BeaconBlockMessage,
}
fn parse<'de, T, D>(de: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    Ok(String::deserialize(de)?.parse().map_err(serde::de::Error::custom)?)
}

#[derive(serde::Deserialize, serde::Serialize)]
struct BeaconBlockMessage {
    #[serde(deserialize_with = "parse")]
    slot: u64,
}

pub async fn get_assigned_validator(url: &str, slot: u64) -> Result<Option<BlsPublicKey>, Error> {
    let url = format!("{url}/relay/v1/builder/delegations");
    let delegations: Vec<SignedDelegation> =
        Client::new().get(url).query(&[("slot", slot)]).send().await?.json().await?;
    Ok(delegations
        .into_iter()
        .filter_map(|delegation| {
            if delegation.message.action == DELEGATION_ACTION {
                Some(delegation.message.delegatee_pubkey)
            } else {
                None
            }
        })
        .next())
}

pub async fn get_head_slot(url: &str) -> Result<u64, Error> {
    let url = format!("{url}/eth/v2/beacon/blocks/head");
    let block: BeaconBlock = Client::new().get(url).send().await?.json().await?;
    Ok(block.data.message.slot)
}

pub async fn get_initial_assigned_validator<Factory: SlotInfoFactory>(
    beacon_url: &str,
    relay_url: &str,
    slots_per_epoch: u64,
    underwriter_pubkey: BlsPublicKey,
    factory: Factory,
) -> Result<Vec<SlotInfo>, Error> {
    let head_slot = get_head_slot(beacon_url).await?;
    let epoch = head_slot / slots_per_epoch;
    let mut available_slots = vec![];
    for slot in (head_slot + 1)..(epoch + 2) * slots_per_epoch {
        if let Some(assigned_validator) = get_assigned_validator(relay_url, slot).await? {
            if assigned_validator == underwriter_pubkey {
                available_slots.push(factory.slot_info(slot));
            }
        }
    }
    Ok(available_slots)
}
