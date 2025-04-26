use std::str::FromStr;

use alloy_network::EthereumWallet;
use alloy_primitives::{keccak256, Address, Bytes};
use alloy_provider::ProviderBuilder;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue;
use clap::Parser;
use eyre::Result;
use reqwest::Url;
use taiyi_contracts::AllocationManager;
use tracing::info;

#[derive(Debug, Parser)]
pub struct RegisterForOperatorSetsCommand {
    /// The RPC URL of the Ethereum node
    #[clap(long, env = "EXECUTION_RPC_URL")]
    execution_rpc_url: String,

    /// Tx signer private key
    #[clap(long, env = "PRIVATE_KEY")]
    private_key: String,

    /// Operator BLS key
    #[clap(long, env = "OPERATOR_BLS_KEY")]
    operator_bls_key: String,

    /// AVS address
    #[clap(long)]
    avs_address: Address,

    /// Allocation Manager contract address
    #[clap(long)]
    allocation_manager_address: Address,

    /// Operator set IDs (comma-separated list of uint32 values)
    #[clap(long, value_delimiter = ',')]
    operator_set_ids: Vec<u32>,

    #[clap(long)]
    socket: String,
}

impl RegisterForOperatorSetsCommand {
    pub async fn execute(&self) -> Result<()> {
        let signer: PrivateKeySigner = self.private_key.parse()?;
        let operator_address = signer.address();
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::new(signer.clone()))
            .on_http(Url::from_str(&self.execution_rpc_url)?);

        let allocation_manager =
            AllocationManager::new(self.allocation_manager_address, provider.clone());
        let bls_pub_key = Bytes::from_str(&self.operator_bls_key)?;

        let mut signing_target: Vec<u8> = Vec::new();
        signing_target.extend(operator_address.to_vec());
        signing_target.extend(bls_pub_key.to_vec());
        let message_hash = keccak256(signing_target);
        let signature = signer.sign_hash_sync(&message_hash)?;

        let pubkey_params = AllocationManager::PubkeyRegistrationParams {
            blsPubkey: bls_pub_key,
            operator: operator_address,
            pubkeyRegistrationSignature: Bytes::from(signature.as_bytes().to_vec()),
        };

        let data = Bytes::from((self.socket.clone(), pubkey_params).abi_encode_sequence());

        // Create the RegisterParams struct
        let params = AllocationManager::RegisterParams {
            avs: self.avs_address,
            operatorSetIds: self.operator_set_ids.clone(),
            data,
        };
        // Register the operator for the operator sets
        let res =
            allocation_manager.registerForOperatorSets(operator_address, params).send().await?;

        info!("Transaction sent! Hash: {:?}", res.tx_hash());

        Ok(())
    }
}
