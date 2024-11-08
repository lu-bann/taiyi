use std::str::FromStr;

use alloy_primitives::{keccak256, Address, Bytes};
use alloy_provider::ProviderBuilder;
use alloy_sol_types::sol;
use clap::Parser;
use tracing::info;
use TaiyiCore::TaiyiCoreInstance;

#[derive(Debug, Parser)]
pub struct GetDelegatedPreconferCommand {
    /// rpc url
    #[clap(long = "rpc_url")]
    pub rpc_url: String,

    /// taiyi core contract address
    #[clap(long = "taiyi_core_contract_addr")]
    pub taiyi_core_contract_addr: String,

    #[clap(long = "proposer_pubkey")]
    pub proposer_pubkey: String,
}

sol! {

    #[derive(Debug)]
    struct PreconferElection {
        bytes validatorPubkey;
        bytes preconferPubkey;
        uint256 chainId;
        address preconferAddress;
    }

    #[sol(rpc)]
    contract TaiyiCore {
        #[derive(Debug)]
        function getPreconferElection(bytes calldata validatorPubKey) external view returns (PreconferElection memory) ;
    }


}

impl GetDelegatedPreconferCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        // Connect to the Ethereum network
        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&self.rpc_url).await?;

        // Parse contract address
        let taiyi_core_address: Address = self.taiyi_escrow_contract_addr.parse()?;
        let taiyi_core = TaiyiCoreInstance::new(taiyi_core_address, provider.clone());

        let proposer_pubkey = Bytes::from_str(&self.proposer_pubkey)?;
        let validator_pubkey_hash = keccak256(proposer_pubkey.clone());

        info!("validator_pubkey_hash: {:?}", validator_pubkey_hash);

        let get_delegated_preconfer = taiyi_core.getPreconferElection(proposer_pubkey);
        let call = get_delegated_preconfer.call();

        info!("{call:?}");

        let result = call.await?;

        info!("{result:?}");

        Ok(())
    }
}
