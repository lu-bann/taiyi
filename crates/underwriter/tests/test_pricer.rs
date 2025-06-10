use std::{str::FromStr, time::Duration};

use alloy_provider::{Provider, ProviderBuilder};
use reqwest::Url;
use taiyi_underwriter::clients::pricer::{ExecutionClientPricer, PreconfPricer, TaiyiPricer};

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
