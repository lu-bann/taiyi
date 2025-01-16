use alloy_network::EthereumWallet;
use alloy_primitives::{Address, U256};
use alloy_provider::ProviderBuilder;
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use eyre::Result;
use taiyi_contracts::{IStrategy, IStrategyManager, IERC20};
use tracing::info;

#[derive(Debug, Parser)]
pub struct DepositCommand {
    /// The RPC URL of the Ethereum node
    #[clap(long, env = "EXECUTION_RPC_URL")]
    execution_rpc_url: String,

    /// The strategy contract address
    #[clap(long, env = "STRATEGY_ADDRESS")]
    strategy_address: Address,

    /// Amount to deposit
    #[clap(long, env = "AMOUNT")]
    amount: U256,

    /// Private key for signing transactions
    #[clap(long, env = "PRIVATE_KEY")]
    private_key: String,

    /// The strategy manager contract address
    #[clap(long, env = "STRATEGY_MANAGER_ADDRESS")]
    strategy_manager_address: Address,
}

impl DepositCommand {
    pub async fn execute(&self) -> Result<()> {
        // Setup provider and signer
        // Create a wallet from the private key
        let signer: PrivateKeySigner = self.private_key.parse()?;
        // Connect to the Ethereum network
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::new(signer.clone()))
            .on_builtin(&self.execution_rpc_url)
            .await?;

        // Create Strategy contract interface
        let strategy = IStrategy::new(self.strategy_address, provider.clone());

        // Get underlying token address
        let token_address = strategy.underlyingToken().call().await?;
        let token_address = token_address._0;
        info!("Underlying token address: {:?}", token_address);

        // Create ERC20 interface for the token
        let token = IERC20::new(token_address, provider.clone());

        // Create StrategyManager interface (you'll need to get this address from your deployment or config)
        let strategy_manager =
            IStrategyManager::new(self.strategy_manager_address, provider.clone());

        // Approve token spending
        let approve_tx = token.approve(self.strategy_manager_address, self.amount).send().await?;
        info!("Approving token transfer {}", approve_tx.tx_hash());

        let receipt = approve_tx.get_receipt().await?;
        info!("Token approval confirmed {:?}", receipt.transaction_hash);

        // Deposit into strategy
        let deposit_tx = strategy_manager
            .depositIntoStrategy(self.strategy_address, token_address, self.amount)
            .send()
            .await?;
        info!(
            "Depositing into strategy at {} with tx {}",
            self.strategy_address,
            deposit_tx.tx_hash()
        );

        let receipt = deposit_tx.get_receipt().await?;
        info!("Deposit successful! Transaction hash: {:?}", receipt.transaction_hash);

        Ok(())
    }
}
