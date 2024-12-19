use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use taiyi_cmd::initialize_tracing_log;
use tracing::info;

use crate::{
    constant::{PRECONFER_BLS_PK, SIGNER_PRIVATE},
    utils::{
        generate_tx, get_available_slot, get_constraints_from_relay, get_estimate_fee, setup_env,
        submit_preconf_request, wait_until_slot, wati_until_deadline_of_slot, TestConfig,
    },
};

#[tokio::test]
async fn test_with_taiyi_command() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;

    let available_slot = get_available_slot(&config.taiyi_url()).await?;

    let target_slot = available_slot.first().unwrap().slot;

    let tx = generate_tx(&config.execution_url, SIGNER_PRIVATE).await?;
    let _submit_res = submit_preconf_request(&config.taiyi_url(), &tx, target_slot).await?;

    wati_until_deadline_of_slot(&config, target_slot).await?;

    let constraints = get_constraints_from_relay(&config.relay_url, target_slot).await?;

    assert_eq!(constraints.len(), 1);

    let signed_constraints = constraints.first().unwrap().clone();
    let message = signed_constraints.message;

    let tx_ret = message.decoded_tx().unwrap().first().unwrap().clone();

    assert_eq!(
        message.pubkey,
        BlsPublicKey::try_from(hex::decode(PRECONFER_BLS_PK).unwrap().as_slice()).unwrap()
    );

    assert_eq!(message.slot, target_slot);

    assert_eq!(tx_ret, tx);

    // Optionally, cleanup when done
    taiyi_handle.abort();
    Ok(())
}
#[tokio::test]
async fn test_estimate_fee() -> eyre::Result<()> {
    // Start taiyi command in background
    let (taiyi_handle, config) = setup_env().await?;

    let available_slot = get_available_slot(&config.taiyi_url()).await?;

    let target_slot = available_slot.first().unwrap().slot;

    let estimate_fee = get_estimate_fee(&config.taiyi_url(), target_slot).await?;

    info!("estimate_fee: {:?}", estimate_fee);
    taiyi_handle.abort();
    Ok(())
}
