use alloy_network::EthereumWallet;
use alloy_primitives::{Address, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use clap::Parser;
use tracing::info;

#[derive(Debug, Parser)]
pub struct LubanEscrowDepositCommand {
    /// rpc url
    #[clap(long = "rpc_url")]
    pub rpc_url: String,

    /// Private key in hex format
    #[clap(long = "private_key")]
    pub private_key: String,

    /// luban escrow contract address
    #[clap(long = "luban_escrow_contract_addr")]
    pub luban_escrow_contract_addr: String,

    #[clap(long = "amount")]
    pub amount: U256,
}

sol! {
    #[sol(rpc)]
    contract LubanEscrow {
        #[derive(Debug)]
        function deposit() public payable;
    }
}

impl LubanEscrowDepositCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        // Create a wallet from the private key
        let signer: PrivateKeySigner = self.private_key.parse()?;
        // Connect to the Ethereum network
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::new(signer))
            .on_builtin(&self.rpc_url)
            .await?;

        // Parse contract address
        let contract_address: Address = self.luban_escrow_contract_addr.parse()?;
        // Create contract instance
        let luban_escrow = LubanEscrow::new(contract_address, provider.clone());

        // Call deposit function
        let tx = luban_escrow
            .deposit()
            .value(self.amount)
            .into_transaction_request();

        let pending_tx = provider.send_transaction(tx).await?;

        info!("Transaction sent: {:?}", pending_tx.tx_hash());

        // Wait for transaction to be mined
        let receipt = pending_tx.get_receipt().await?;
        info!("Transaction mined in block: {:?}", receipt.block_number);

        Ok(())
    }
}
