use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use taiyi_primitives::{encode_util::hex_encode, PreconfRequest, PreconfResponseData};
use tokio::sync::broadcast;
use uuid::Uuid;

pub type SendError =
    tokio::sync::broadcast::error::SendError<(PreconfRequest, PreconfResponseData)>;

#[cfg_attr(test, mockall::automock)]
pub trait Sender {
    fn sign_and_send(
        &self,
        id: Uuid,
        request: PreconfRequest,
    ) -> impl Future<Output = Result<(), SendError>>;
}

#[derive(Debug, Clone)]
pub struct BroadcastSender {
    signer: PrivateKeySigner,
    chain_id: u64,
    last_slot: Arc<AtomicU64>,
    broadcast_sender: broadcast::Sender<(PreconfRequest, PreconfResponseData)>,
}

impl BroadcastSender {
    pub fn new(signer: PrivateKeySigner, chain_id: u64, last_slot: Arc<AtomicU64>) -> Self {
        Self { signer, chain_id, last_slot, broadcast_sender: broadcast::channel(128).0 }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<(PreconfRequest, PreconfResponseData)> {
        self.broadcast_sender.subscribe()
    }
}

impl Sender for BroadcastSender {
    async fn sign_and_send(&self, id: Uuid, request: PreconfRequest) -> Result<(), SendError> {
        let signature =
            self.signer.sign_hash(&request.digest(self.chain_id)).await.expect("Add error");

        let response = PreconfResponseData {
            request_id: id,
            commitment: Some(hex_encode(signature.as_bytes())),
            sequence_num: None,
            current_slot: self.last_slot.load(Ordering::Relaxed) + 1,
        };

        self.broadcast_sender.send((request, response))?;
        Ok(())
    }
}
