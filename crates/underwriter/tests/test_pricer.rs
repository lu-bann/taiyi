use std::{str::FromStr, time::Duration};

use alloy_provider::{Provider, ProviderBuilder};
use reqwest::Url;
use taiyi_underwriter::clients::pricer::{ExecutionClientPricer, PreconfPricer, TaiyiPricer};

#[ignore = "requires a running pricing service"]
#[tokio::test]
async fn test_taiyi_pricer() {
    let pricer_url = std::env::var("PRICER_URL").unwrap();
    let pricer = TaiyiPricer::new(pricer_url);
    let rpc = "https://1rpc.io/holesky";
    // let rpc = "https://eth.merkle.io";
    let provider = ProviderBuilder::new().on_http(rpc.parse().unwrap());
    let block_number = provider.get_block_number().await.unwrap() + 1;

    let preconf_fee = pricer.get_preconf_fee(block_number).await;
    assert!(preconf_fee.is_ok());
    let preconf_fee = preconf_fee.unwrap();
    println!("Preconf fee: {:?}", preconf_fee);
    tokio::time::sleep(Duration::from_secs(12)).await;
    let header = provider
        .get_block_by_number(alloy_eips::BlockNumberOrTag::Number(block_number))
        .await
        .unwrap()
        .unwrap()
        .header;
    println!(
        "actual base fee {:?}, actual blob base fee {:?}",
        header.base_fee_per_gas,
        header.blob_fee()
    );
}

#[tokio::test]
async fn test_execution_client_pricer() -> eyre::Result<()> {
    let anvil = alloy_node_bindings::Anvil::new().block_time(1).chain_id(0).spawn();
    let rpc_url = anvil.endpoint();
    let url = Url::from_str(&rpc_url)?;
    let provider = ProviderBuilder::new().on_http(url);

    let pricer = ExecutionClientPricer::new(provider);
    let preconf_fee = pricer.get_preconf_fee(0).await;
    assert!(preconf_fee.is_ok());
    Ok(())
}
