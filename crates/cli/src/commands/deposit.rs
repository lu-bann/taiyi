use std::str::FromStr;

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, U256};
use alloy_provider::ProviderBuilder;
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use eyre::Result;
use reqwest::Url;
use taiyi_contracts::{
    AllocateParams, AllocationManager, IStrategy, IStrategyManager, OperatorSet, IERC20,
};
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

    /// The allocation manager contract address
    #[clap(long, env = "ALLOCATION_MANAGER_ADDRESS")]
    allocation_manager_address: Address,

    /// When applying scaling factors, they are typically multiplied/divided by `WAD`, allowing this
    /// constant to act as a "1" in mathematical formulae.
    #[clap(long, env = "WAD", default_value = "1000000000000000000")]
    wad: u64,

    /// The operator set id
    #[clap(long, env = "OPERATOR_SET_ID")]
    operator_set_id: u32,

    /// Linglong Eigenlayer middleware address
    #[clap(long, env = "LINGLONG_EIGENLAYER_MIDDLEWARE_ADDRESS")]
    linglong_eigenlayer_middleware_address: Address,
}

impl DepositCommand {
    pub async fn execute(&self) -> Result<()> {
        // Setup provider and signer
        // Create a wallet from the private key
        let signer: PrivateKeySigner = self.private_key.parse()?;
        // Connect to the Ethereum network
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::new(signer.clone()))
            .connect_http(Url::from_str(&self.execution_rpc_url)?);

        // Create Strategy contract interface
        let strategy = IStrategy::new(self.strategy_address, provider.clone());

        // Get underlying token address
        let token_address = strategy.underlyingToken().call().await?;
        let token_address = token_address;
        info!("Underlying token address: {:?}", token_address);

        // Create ERC20 interface for the token
        let token = IERC20::new(token_address, provider.clone());

        // Check user's balance before proceeding
        let signer_address = signer.address();
        let balance = token.balanceOf(signer_address).call().await?;
        info!("Strategy Token Balance of signer: {:?}", balance);
        if balance < self.amount {
            return Err(eyre::eyre!(
                "Insufficient balance. Required: {}, Available: {}",
                self.amount,
                balance
            ));
        }
        info!("Balance check passed. Available: {}, Required: {}", balance, self.amount);

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

        let allocation_manager =
            AllocationManager::new(self.allocation_manager_address, provider.clone());

        let allocation_tx = allocation_manager
            .modifyAllocations(
                signer_address,
                vec![AllocateParams {
                    operatorSet: OperatorSet {
                        avs: self.linglong_eigenlayer_middleware_address,
                        id: self.operator_set_id,
                    },
                    strategies: vec![self.strategy_address],
                    newMagnitudes: vec![self.wad],
                }],
            )
            .send()
            .await?;
        info!("Allocation successful! Transaction hash: {:?}", allocation_tx.tx_hash());
        let receipt = allocation_tx.get_receipt().await?;
        info!("Allocation confirmed! Transaction hash: {:?}", receipt.transaction_hash);
        Ok(())
    }
}
