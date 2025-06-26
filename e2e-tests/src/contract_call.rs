use std::ops::Add;

use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, U256};
use alloy_provider::{
    network::{EthereumWallet, TransactionBuilder},
    Provider, ProviderBuilder,
};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use tracing::info;

use crate::{constant::REVERTER_CONTRACT_ADDRESS, utils::TestConfig, TestProvider};

sol! {
    #[sol(rpc)]
    contract TaiyiEscrow {
        #[derive(Debug)]
        function balanceOf(address user) public view returns (uint256);

        #[derive(Debug)]
        function deposit() public payable;
    }
}

sol! {
    #[sol(rpc)]
    contract Reverter {
        function revertFromRevert() public pure;
    }
}

pub async fn taiyi_deposit(
    provider: TestProvider,
    amount: u128,
    test_config: &TestConfig,
) -> eyre::Result<()> {
    let fees = provider.estimate_eip1559_fees().await?;
    info!("Fees: {:?}", fees);
    let taiyi_escrow = TaiyiEscrow::new(test_config.taiyi_core, provider.clone());
    // Call deposit function
    let tx = taiyi_escrow
        .deposit()
        .value(U256::from(amount))
        .into_transaction_request()
        .max_fee_per_gas(fees.max_fee_per_gas)
        .max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
    let pending_tx = provider.send_transaction(tx).await?;
    info!("Deposit Transaction sent: {:?}", pending_tx.tx_hash());
    // Wait for transaction to be mined
    let receipt = pending_tx.get_receipt().await?;
    info!("Deposit Transaction mined in block: {:?}", receipt.block_number.unwrap());
    Ok(())
}

pub async fn taiyi_balance(
    provider: TestProvider,
    address: Address,
    test_config: &TestConfig,
) -> eyre::Result<U256> {
    let taiyi_escrow = TaiyiEscrow::new(test_config.taiyi_core, provider.clone());
    let balance = taiyi_escrow.balanceOf(address).call().await?;
    info!("Balance: {:?}", balance);
    Ok(balance)
}

pub async fn revert_call(
    provider: TestProvider,
    wallet: &EthereumWallet,
) -> eyre::Result<TxEnvelope> {
    let contract_address: Address = REVERTER_CONTRACT_ADDRESS.parse()?;
    let revert_contract = Reverter::new(contract_address, provider.clone());
    let mut revert_call_tx = revert_contract.revertFromRevert().into_transaction_request();
    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(wallet.default_signer().address()).await?;
    revert_call_tx.set_nonce(nonce);
    revert_call_tx.set_gas_limit(100000);
    let estimate = provider.estimate_eip1559_fees().await?;
    revert_call_tx.set_max_fee_per_gas(estimate.max_fee_per_gas);
    revert_call_tx.set_max_priority_fee_per_gas(estimate.max_priority_fee_per_gas);
    revert_call_tx.set_chain_id(chain_id);

    let typed_tx = revert_call_tx.build(&wallet).await?;
    Ok(typed_tx)
}
