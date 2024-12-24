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

        let current_time =
            SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();
        let genesis_time = context.genesis_time().unwrap();

        let target_slot = (current_time - genesis_time) / context.seconds_per_slot + 2;

        let request = BlockspaceAllocation {
            target_slot,
            deposit: U256::ZERO,
            gas_limit: 21_0000,
            num_blobs: 0,
        };
        let signature = hex::encode(signer.sign_hash(&request.digest()).await?.as_bytes());

        let endpoint = Url::parse(&server_endpoint).unwrap().join(RESERVE_BLOCKSPACE_PATH).unwrap();
        let response = reqwest::Client::new()
            .post(endpoint.clone())
            .header("content-type", "application/json")
            .header("x-luban-signature", format!("{}:0x{}", signer.address(), signature))
            .json(&request)
            .send()
            .await?;
        let status = response.status();
        let body = response.bytes().await?;
        println!("body: {:?}", body);
        assert_eq!(status, 200);
        let request_id: Uuid = serde_json::from_slice(&body)?;
        info!("request_id: {:?}", request_id);

        // Test sending a allocation request without a transaction and then sending a transaction with the request_id
        let fees = provider.estimate_eip1559_fees(None).await?;
        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::from(1000))
            .with_nonce(0)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .build(&wallet)
            .await?;

        let send_transaction_endpoint =
            Url::parse(&server_endpoint).unwrap().join(SUBMIT_TRANSACTION_PATH).unwrap();
        let request = SubmitTransactionRequest { request_id, transaction: transaction.clone() };
        let signature = hex::encode(signer.sign_hash(&request.digest()).await?.as_bytes());
        let response = reqwest::Client::new()
            .post(send_transaction_endpoint.clone())
            .header("content-type", "application/json")
            .header("x-luban-signature", format!("0x{}", signature))
            .json(&request)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        info!("status: {}", status);
        info!("body: {}", body);
        assert_eq!(status, 200);

        Ok(())
    }
}
