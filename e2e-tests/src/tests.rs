use std::str::FromStr;

use alloy_primitives::Address;
use alloy_provider::{network::EthereumWallet, Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use tracing::info;

use crate::{
    constant::{PRECONFER_BLS_PK, SIGNER_PRIVATE},
    utils::{
        generate_reserve_blockspace_request, generate_tx, get_available_slot,
        get_constraints_from_relay, get_estimate_fee, send_reserve_blockspace_request, setup_env,
        submit_preconf_request, wati_until_deadline_of_slot,
    },
};

sol! {
    #[sol(rpc)]
    contract TaiyiEscrow {
        #[derive(Debug)]
        function balanceOf(address user) public view returns (uint256);

        #[derive(Debug)]
        function deposit() public payable;
    }
}

#[tokio::test]
async fn test_commitment_apis() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;

    let available_slot = get_available_slot(&config.taiyi_url()).await?;
    let target_slot = available_slot.first().unwrap().slot;

    let fee = get_estimate_fee(&config.taiyi_url(), target_slot).await?;

    // Generate request and signature
    let (request, signature) =
        generate_reserve_blockspace_request(SIGNER_PRIVATE, target_slot, fee.fee).await;

    // Deposit into escrow contract
    let signer: PrivateKeySigner = SIGNER_PRIVATE.parse()?;
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(EthereumWallet::new(signer))
        .on_builtin(&config.execution_url)
        .await?;

    let contract_address: Address = "0xA791D59427B2b7063050187769AC871B497F4b3C".parse()?;
    let taiyi_escrow = TaiyiEscrow::new(contract_address, provider.clone());
    // Call deposit function
    let tx = taiyi_escrow.deposit().value(request.deposit).into_transaction_request();
    let pending_tx = provider.send_transaction(tx).await?;
    info!("Transaction sent: {:?}", pending_tx.tx_hash());
    // Wait for transaction to be mined
    let receipt = pending_tx.get_receipt().await?;
    info!("Transaction mined in block: {:?}", receipt.block_number);

    let res = send_reserve_blockspace_request(request, signature, &config.taiyi_url()).await?;
    assert_eq!(res, 200);

    // let tx = generate_tx(&config.execution_url, SIGNER_PRIVATE).await?;
    // let _submit_res = submit_preconf_request(&config.taiyi_url(), &tx).await?;

    // wati_until_deadline_of_slot(&config, target_slot).await?;

    // let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;

    // assert_eq!(constraints.len(), 1);

    // let signed_constraints = constraints.first().unwrap().clone();
    // let message = signed_constraints.message;

    // let tx_ret = message.decoded_tx().unwrap().first().unwrap().clone();

    // assert_eq!(
    //     message.pubkey,
    //     BlsPublicKey::try_from(hex::decode(PRECONFER_BLS_PK).unwrap().as_slice()).unwrap()
    // );

    // assert_eq!(message.slot, target_slot);

    // assert_eq!(tx_ret, tx);

    // Optionally, cleanup when done
    taiyi_handle.abort();
    Ok(())
}
