use std::future::Future;
use taiyi_primitives::{PreconfRequest, PreconfResponseData};
use tokio::sync::broadcast;

pub type SendError =
    tokio::sync::broadcast::error::SendError<(PreconfRequest, PreconfResponseData)>;

#[cfg_attr(test, mockall::automock)]
pub trait Sender {
    fn send(
        &self,
        request: PreconfRequest,
        response: PreconfResponseData,
    ) -> impl Future<Output = Result<(), SendError>>;
}

#[derive(Debug, Clone)]
pub struct BroadcastSender {
    broadcast_sender: broadcast::Sender<(PreconfRequest, PreconfResponseData)>,
}

impl BroadcastSender {
    pub fn new(sender: broadcast::Sender<(PreconfRequest, PreconfResponseData)>) -> Self {
        Self { broadcast_sender: sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<(PreconfRequest, PreconfResponseData)> {
        self.broadcast_sender.subscribe()
    }
}

impl Sender for BroadcastSender {
    async fn send(
        &self,
        request: PreconfRequest,
        response: PreconfResponseData,
    ) -> Result<(), SendError> {
        self.broadcast_sender.send((request, response))?;
        Ok(())
    }
}
