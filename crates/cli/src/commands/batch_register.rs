use std::str::FromStr;

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use clap::Parser;
use tracing::info;
use ProposerRegistry::ProposerRegistryInstance;

#[derive(Debug, Parser)]
pub struct BatchRegisterCommand {
    /// rpc url
    #[clap(long = "rpc_url")]
    pub rpc_url: String,

    /// Private key in hex format
    #[clap(long = "private_key")]
    pub private_key: String,

    /// taiyi proposer registry contract address
    #[clap(long = "taiyi_proposer_registry_contract_addr")]
    pub taiyi_proposer_registry_contract_addr: String,

    #[clap(long = "proposer_pubkeys", value_delimiter = ',')]
    pub proposer_pubkey: Vec<String>,
}

sol! {
    #[derive(Debug)]
    struct PreconferElection {
        bytes validatorPubkey;
        uint256 chainId;
        address preconferAddress;
    }

    #[sol(rpc)]
    contract ProposerRegistry {
        #[derive(Debug)]
        function batchRegisterValidators(bytes[] calldata pubkeys) external payable;
    }
}

impl BatchRegisterCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        // Create a wallet from the private key
        let signer: PrivateKeySigner = self.private_key.parse()?;
        // Connect to the Ethereum network
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::new(signer.clone()))
            .on_builtin(&self.rpc_url)
            .await?;

        let chain_id = provider.get_chain_id().await?;

        // Parse contract address
        let proposer_registry_address: Address =
            self.taiyi_proposer_registry_contract_addr.parse()?;
        let proposer_registry =
            ProposerRegistryInstance::new(proposer_registry_address, provider.clone());

        let mut proposer_duties = Vec::with_capacity(self.proposer_pubkey.len());
        let mut proposer_pubkeys = Vec::with_capacity(self.proposer_pubkey.len());
        info!("preconfer address: {:?}", signer.address());
        for proposer_pubkey in self.proposer_pubkey.iter() {
            let proposer_pubkey = Bytes::from_str(proposer_pubkey)?;
            let proposer_dury = PreconferElection {
                validatorPubkey: proposer_pubkey.clone(),
                chainId: U256::from(chain_id),
                preconferAddress: signer.address(),
            };
            proposer_pubkeys.push(proposer_pubkey);
            proposer_duties.push(proposer_dury);
        }

        info!("signer address: {:?}", signer.address());
        // Call deposit function
        let tx = proposer_registry
            .batchRegisterValidators(proposer_pubkeys)
            .into_transaction_request()
            .from(signer.address());

        let pending_tx = provider.send_transaction(tx).await?;

        info!(
            "Register validator to proposer registry Transaction sent: {:?}",
            pending_tx.tx_hash()
        );

        // Wait for transaction to be mined
        let receipt = pending_tx.get_receipt().await?;
        info!(
            "Register validator to proposer registry Transaction mined in block: {:?}",
            receipt.block_number
        );
        Ok(())
    }
}
