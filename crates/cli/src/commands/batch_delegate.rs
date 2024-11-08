use std::str::FromStr;

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use clap::Parser;
use tracing::info;
use ProposerRegistry::ProposerRegistryInstance;
use TaiyiCore::TaiyiCoreInstance;

#[derive(Debug, Parser)]
pub struct BatchDelegateCommand {
    /// rpc url
    #[clap(long = "rpc_url")]
    pub rpc_url: String,

    /// Private key in hex format
    #[clap(long = "private_key")]
    pub private_key: String,

    /// taiyi core contract address
    #[clap(long = "taiyi_core_contract_addr")]
    pub taiyi_core_contract_addr: String,

    /// taiyi proposer registry contract address
    #[clap(long = "taiyi_proposer_registry_contract_addr")]
    pub taiyi_proposer_registry_contract_addr: String,

    #[clap(long = "proposer_pubkeys", value_delimiter = ',')]
    pub proposer_pubkey: Vec<String>,

    #[clap(long = "preconfer_pubkey")]
    pub preconfer_pubkey: String,
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
        function batchDelegatePreconfDuty(PreconferElection[] calldata preconferElections) external;
    }


    #[sol(rpc)]
    contract ProposerRegistry {
        #[derive(Debug)]
        function batchRegisterValidators(bytes[] calldata pubkeys, address[] calldata delegatees) external payableW;
    }
}

impl BatchDelegateCommand {
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
        let taiyi_core_address: Address = self.taiyi_escrow_contract_addr.parse()?;
        let taiyi_core = TaiyiCoreInstance::new(taiyi_core_address, provider.clone());
        let proposer_registry_address: Address =
            self.taiyi_proposer_registry_contract_addr.parse()?;
        let proposer_registry =
            ProposerRegistryInstance::new(proposer_registry_address, provider.clone());

        let preconfer_pubkey = Bytes::from_str(&self.preconfer_pubkey)?;

        let mut proposer_duties = Vec::with_capacity(self.proposer_pubkey.len());
        let mut delegatees = Vec::with_capacity(self.proposer_pubkey.len());
        let mut proposer_pubkeys = Vec::with_capacity(self.proposer_pubkey.len());
        info!("preconfer address: {:?}", signer.address());
        for proposer_pubkey in self.proposer_pubkey.iter() {
            let proposer_pubkey = Bytes::from_str(proposer_pubkey)?;
            let proposer_dury = PreconferElection {
                validatorPubkey: proposer_pubkey.clone(),
                preconferPubkey: preconfer_pubkey.clone(),
                chainId: U256::from(chain_id),
                preconferAddress: signer.address(),
            };
            proposer_pubkeys.push(proposer_pubkey);
            proposer_duties.push(proposer_dury);
            delegatees.push(signer.address());
        }

        info!("signer address: {:?}", signer.address());
        // Call deposit function
        let tx = proposer_registry
            .batchRegisterValidators(proposer_pubkeys, delegatees)
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

        let tx = taiyi_core
            .batchDelegatePreconfDuty(proposer_duties)
            .into_transaction_request()
            .from(signer.address());

        let pending_tx = provider.send_transaction(tx).await?;

        info!("Delegate preconfer duty Transaction sent: {:?}", pending_tx.tx_hash());

        let receipt = pending_tx.get_receipt().await?;
        info!("Delegate preconfer duty Transaction mined in block: {:?}", receipt.block_number);
        Ok(())
    }
}
