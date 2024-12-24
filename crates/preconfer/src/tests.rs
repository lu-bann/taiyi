mod tests {
    #![allow(unused_variables)]

    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
        time::{SystemTime, UNIX_EPOCH},
    };

    use alloy_network::{EthereumWallet, TransactionBuilder};
    use alloy_node_bindings::Anvil;
    use alloy_primitives::{hex, keccak256, Address, U256};
    use alloy_provider::{Provider, ProviderBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer::Signer;
    use alloy_signer_local::PrivateKeySigner;
    use ethereum_consensus::deneb::Context;
    use k256::{ecdsa::VerifyingKey, Secp256k1};
    use reqwest::Url;
    use secp256k1::{ecdsa::Signature as EcdsaSignature, Message, PublicKey as EcdsaPublicKey};
    use taiyi_primitives::{
        BlockspaceAllocation, PreconfRequest, PreconfResponse, SubmitTransactionRequest,
    };
    use tracing::info;
    use uuid::Uuid;

    use crate::{
        clients::{
            execution_client::ExecutionClient, relay_client::RelayClient,
            signer_client::SignerClient,
        },
        network_state::NetworkState,
        preconf_api::{
            api::{PreconfApiServer, RESERVE_BLOCKSPACE_PATH, SUBMIT_TRANSACTION_PATH},
            state::PreconfState,
        },
    };

    #[ignore]
    #[tokio::test]
    async fn test_preconf_api_server() -> eyre::Result<()> {
        let context = Context::for_mainnet();
        let network_state = NetworkState::new(context.clone());
        let relay_client = RelayClient::new(vec![]);

        let bls_sk = "4bd1960f5721d636400cb9dff7d17d5cfcc155f113280b8b9158596e2c0084ce".to_string();
        let ecdsa_sk =
            "0xa37e56991c7e88b7a4d80010a729fecce48fb2da505f3dccab7c2fa89bb69c4f".to_string();
        let ecdsa_pubkey =
            "03643b2c19f03891a7d103f50fab07ad0dbe7cb19477074d42488a28e345b07145".to_string();
        let signer_client = SignerClient::new(bls_sk, ecdsa_sk)?;

        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();
        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;

        // spawn api server
        let state = PreconfState::new(
            network_state,
            relay_client,
            signer_client.clone(),
            rpc_url.parse().unwrap(),
        );
        let preconfapiserver =
            PreconfApiServer::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5656));
        let server_endpoint = preconfapiserver.endpoint();
        let _ = preconfapiserver.run(state.clone()).await;

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        Ok(())
    }
}
