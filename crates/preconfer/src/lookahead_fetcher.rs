use alloy_core::primitives::Address;
use alloy_network::Ethereum;
use alloy_provider::Provider;
use alloy_sol_types::sol;
use alloy_transport::Transport;
use beacon_api_client::{mainnet::Client, ProposerDuty};
use futures::TryStreamExt;
use mev_share_sse::EventClient;
use reqwest::Url;
use reth::core::rpc::types::beacon::events::HeadEvent;
use tokio::sync::mpsc::Sender;
use LubanProposerRegistry::LubanProposerRegistryInstance;

sol! {
    #[sol(rpc)]
    contract LubanProposerRegistry {
        #[derive(Debug)]
        function isOptedIn(address _proposer) external view returns (bool);
    }
}

pub struct LookaheadFetcher<T, P> {
    client: Client,
    sender: Sender<Vec<ProposerDuty>>,
    _luban_proposer_registry_contract: LubanProposerRegistryInstance<T, P>,
}

impl<T, P> LookaheadFetcher<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    pub fn new(
        provider: P,
        beacon_url: String,
        sender: Sender<Vec<ProposerDuty>>,
        luban_proposer_registry_contract_addr: Address,
    ) -> Self {
        Self {
            client: Client::new(Url::parse(&beacon_url).expect("Invalid URL")),
            sender,
            _luban_proposer_registry_contract: LubanProposerRegistryInstance::new(
                luban_proposer_registry_contract_addr,
                provider,
            ),
        }
    }

    pub async fn run(&self) -> eyre::Result<()> {
        let mut proposer_duties: Vec<ProposerDuty>;

        let client = EventClient::new(reqwest::Client::default());
        let beacon_url_head_event = format!(
            "{}eth/v1/events?topics=head/",
            self.client.endpoint.as_str()
        );
        let mut stream: mev_share_sse::client::EventStream<HeadEvent> =
            client.subscribe(&beacon_url_head_event).await?;
        while let Some(event) = stream.try_next().await? {
            let slot = event.slot;
            let epoch = slot / 32;
            let (_, duties) = self.client.get_proposer_duties(epoch).await?;
            if event.epoch_transition {
                proposer_duties = duties
            } else {
                proposer_duties = duties
                    .into_iter()
                    .filter(|duty| duty.slot > slot)
                    .collect::<Vec<ProposerDuty>>();
            }
            let opt_in_proposer: Vec<ProposerDuty> = proposer_duties
                .into_iter()
                .filter(|_duty| {
                    todo!()
                    // self.luban_proposer_registry_contract
                    //     .isOptedIn(duty.proposer)
                    //     .call()
                    //     .await?
                })
                .collect();
            self.sender.send(opt_in_proposer).await?;
        }

        Ok(())
    }
}
