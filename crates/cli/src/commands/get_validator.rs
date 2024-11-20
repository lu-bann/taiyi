use std::str::FromStr;

use alloy_primitives::{keccak256, Address, Bytes};
use alloy_provider::ProviderBuilder;
use alloy_sol_types::sol;
use clap::Parser;
use tracing::info;
use ProposerRegistry::ProposerRegistryInstance;

#[derive(Debug, Parser)]
pub struct GetValidatorCommand {
    /// rpc url
    #[clap(long = "rpc_url")]
    pub rpc_url: String,

    /// proposer registry contract address
    #[clap(long = "proposer_registry_address")]
    pub proposer_registry_address: String,

    #[clap(long = "proposer_pubkey")]
    pub proposer_pubkey: String,
}

sol! {
    #[derive(Debug)]
    enum ProposerStatus {
        OptedOut,
        OptIn,
        OptingOut
    }
    #[derive(Debug)]
    struct Validator {
        bytes pubkey;
        ProposerStatus status;
        uint256 optOutTimestamp;
        address registrar;
    }

    #[sol(rpc)]
    contract ProposerRegistry {
        #[derive(Debug)]
        function getValidator(bytes32 pubKeyHash) public view returns (Validator memory);
    }


}

impl GetValidatorCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        // Connect to the Ethereum network
        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&self.rpc_url).await?;

        let proposer_registry_address: Address = self.proposer_registry_address.parse()?;
        // Parse contract address
        let proposer_registry =
            ProposerRegistryInstance::new(proposer_registry_address, provider.clone());

        let proposer_pubkey = Bytes::from_str(&self.proposer_pubkey)?;
        let validator_pubkey_hash = keccak256(proposer_pubkey.clone());

        info!("validator_pubkey_hash: {:?}", validator_pubkey_hash);

        let get_delegated_preconfer = proposer_registry.getValidator(validator_pubkey_hash);
        let call = get_delegated_preconfer.call();

        info!("{call:?}");

        let result = call.await?;

        info!("{result:?}");

        Ok(())
    }
}
