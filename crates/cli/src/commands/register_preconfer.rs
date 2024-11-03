use alloy_network::EthereumWallet;
use alloy_primitives::Address;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use clap::Parser;
use tracing::info;
use TaiyiCore::TaiyiCoreInstance;

#[derive(Debug, Parser)]
pub struct RegisterPreconferCommand {
    /// rpc url
    #[clap(long = "rpc_url")]
    pub rpc_url: String,

    /// Private key in hex format
    #[clap(long = "private_key")]
    pub private_key: String,

    /// taiyi escrow contract address
    #[clap(long = "taiyi_core_contract_addr")]
    pub taiyi_core_contract_addr: String,

    #[clap(long = "register_address")]
    pub register_address: String,
}

sol! {

    #[sol(rpc)]
    contract TaiyiCore {
        #[derive(Debug)]
        function registerPreconfer(address Preconfer) external override;
    }


}

impl RegisterPreconferCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        // Create a wallet from the private key
        let signer: PrivateKeySigner = self.private_key.parse()?;
        // Connect to the Ethereum network
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::new(signer.clone()))
            .on_builtin(&self.rpc_url)
            .await?;

        // Parse contract address
        let taiyi_core_address: Address = self.taiyi_core_contract_addr.parse()?;
        let taiyi_core = TaiyiCoreInstance::new(taiyi_core_address, provider.clone());

        let register_address: Address = self.register_address.parse()?;

        let tx = taiyi_core.registerPreconfer(register_address).into_transaction_request();

        let pending_tx = provider.send_transaction(tx).await?;

        info!("Register preconfer Transaction sent: {:?}", pending_tx.tx_hash());

        let receipt = pending_tx.get_receipt().await?;
        info!("Register preconfer Transaction mined in block: {:?}", receipt.block_number);
        Ok(())
    }
}
