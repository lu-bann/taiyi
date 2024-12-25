mod tests {
    #![allow(unused_variables)]

    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
        time::{SystemTime, UNIX_EPOCH},
    };

    use alloy_contract::ContractInstance;
    use alloy_network::{EthereumWallet, TransactionBuilder};
    use alloy_node_bindings::Anvil;
    use alloy_primitives::{hex, keccak256, Address, U256};
    use alloy_provider::{Provider, ProviderBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer::Signer;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::sol;
    use ethereum_consensus::deneb::Context;
    use k256::{ecdsa::VerifyingKey, Secp256k1};
    use reqwest::Url;
    use secp256k1::{ecdsa::Signature as EcdsaSignature, Message, PublicKey as EcdsaPublicKey};
    use taiyi_primitives::{
        BlockspaceAllocation, EstimateFeeRequest, EstimateFeeResponse, PreconfRequest,
        PreconfResponse, SubmitTransactionRequest,
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
            api::{
                PreconfApiServer, ESTIMATE_TIP_PATH, RESERVE_BLOCKSPACE_PATH,
                SUBMIT_TRANSACTION_PATH,
            },
            state::PreconfState,
        },
    };

    sol! {
        #[sol(rpc, bytecode="608060405234801561000f575f80fd5b5060ae8061001c5f395ff3fe6080604052348015600e575f80fd5b50600436106026575f3560e01c806370a0823114602a575b5f80fd5b603b6035366004604d565b505f1990565b60405190815260200160405180910390f35b5f60208284031215605c575f80fd5b81356001600160a01b03811681146071575f80fd5b939250505056fea26469706673582212206c61bd25fef4d1a8213d5b720477f9645de0e38c4005072cb8bc13256564e97f64736f6c63430008140033")]
        contract TaiyiEscrow {
            function balanceOf(address owner) public view returns (uint256 balance) {
                return type(uint256).max;
            }
        }
    }

    #[tokio::test]
    async fn test_preconf_api_server() -> eyre::Result<()> {
        let context = Context::for_mainnet();
        let network_state = NetworkState::new(context.clone());
        let slots = vec![20_000_000];
        for slot in 20_000_000..20_000_000 + 10 {
            network_state.add_slot(slot);
        }

        let relay_client = RelayClient::new(vec![]);

        let bls_sk = "4bd1960f5721d636400cb9dff7d17d5cfcc155f113280b8b9158596e2c0084ce".to_string();
        let ecdsa_sk =
            "0xa37e56991c7e88b7a4d80010a729fecce48fb2da505f3dccab7c2fa89bb69c4f".to_string();
        let ecdsa_pubkey =
            "03643b2c19f03891a7d103f50fab07ad0dbe7cb19477074d42488a28e345b07145".to_string();
        let signer_client = SignerClient::new(bls_sk, ecdsa_sk)?;

        let anvil = Anvil::new().block_time(12).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_builtin(&rpc_url)
            .await?;

        // Deploy escrow contract
        let escrow = TaiyiEscrow::deploy(&provider).await?;
        info!("Deployed contract at address: {}", escrow.address());

        let builder = escrow.balanceOf(*sender);
        let balance = builder.call().await?.balance;
        assert_eq!(balance, U256::MAX);

        // spawn api server
        let state = PreconfState::new(
            network_state.clone(),
            relay_client,
            signer_client.clone(),
            rpc_url.parse().unwrap(),
            *escrow.address(),
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

        // Estimate fee
        let request_endpoint =
            Url::parse(&server_endpoint).unwrap().join(ESTIMATE_TIP_PATH).unwrap();
        let response = reqwest::Client::new()
            .post(request_endpoint.clone())
            .json(&EstimateFeeRequest { slot: *network_state.available_slots().last().unwrap() })
            .send()
            .await?;
        let status = response.status();
        assert_eq!(status, 200);
        let fee: EstimateFeeResponse = response.json().await?;
        assert_eq!(fee.fee, 1);

        // Reserve blockspace
        let request_endpoint =
            Url::parse(&server_endpoint).unwrap().join(RESERVE_BLOCKSPACE_PATH).unwrap();
        let (request, signature) = generate_reserve_blockspace_request(
            signer.clone(),
            *network_state.available_slots().last().unwrap(),
            fee.fee,
        )
        .await;
        let response = reqwest::Client::new()
            .post(request_endpoint.clone())
            .header("content-type", "application/json")
            .header("x-luban-signature", signature)
            .json(&request)
            .send()
            .await?;
        let status = response.status();
        let body = response.bytes().await?;
        println!("{:?}", body);
        let request_id = serde_json::from_slice::<Uuid>(&body)?;
        assert_eq!(status, 200);

        // Submit transaction
        let request_endpoint =
            Url::parse(&server_endpoint).unwrap().join(SUBMIT_TRANSACTION_PATH).unwrap();
        let chain_id = provider.get_chain_id().await?;
        let sender = signer.address();
        let fees = provider.estimate_eip1559_fees(None).await?;
        let nonce = provider.get_transaction_count(sender).await?;
        let transaction = TransactionRequest::default()
            .with_from(sender)
            .with_value(U256::from(1000))
            .with_nonce(nonce)
            .with_gas_limit(21_0000)
            .with_to(sender)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(chain_id)
            .build(&wallet)
            .await?;
        let submit_transaction_request = SubmitTransactionRequest { request_id, transaction };
        let signature = hex::encode(
            signer.sign_hash(&submit_transaction_request.digest()).await.unwrap().as_bytes(),
        );

        let response = reqwest::Client::new()
            .post(request_endpoint.clone())
            .header("content-type", "application/json")
            .header("x-luban-signature", format!("0x{}", signature))
            .json(&submit_transaction_request)
            .send()
            .await?;
        let status = response.status();
        let body = response.bytes().await?;
        println!("{:?}", body);
        println!("Current block number: {:?}", provider.get_block_number().await?);
        let response: PreconfResponse = serde_json::from_slice(&body)?;
        assert_eq!(status, 200);

        Ok(())
    }

    async fn generate_reserve_blockspace_request(
        signer: PrivateKeySigner,
        target_slot: u64,
        fee: u128,
    ) -> (BlockspaceAllocation, String) {
        let request = BlockspaceAllocation {
            target_slot,
            deposit: U256::from(fee * 21_000),
            gas_limit: 21_0000,
            num_blobs: 0,
        };
        let signature = hex::encode(signer.sign_hash(&request.digest()).await.unwrap().as_bytes());
        (request, format!("{}:0x{}", signer.address(), signature))
    }
}
