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
        #[sol(rpc, bytecode="6080604052348015600e575f80fd5b506101c38061001c5f395ff3fe608060405260043610610033575f3560e01c806327e235e31461003757806370a0823114610074578063d0e30db0146100a8575b5f80fd5b348015610042575f80fd5b5061006261005136600461013b565b5f6020819052908152604090205481565b60405190815260200160405180910390f35b34801561007f575f80fd5b5061006261008e36600461013b565b6001600160a01b03165f9081526020819052604090205490565b6100b06100b2565b005b5f34116101165760405162461bcd60e51b815260206004820152602860248201527f4465706f73697420616d6f756e74206d7573742062652067726561746572207460448201526768616e207a65726f60c01b606482015260840160405180910390fd5b335f9081526020819052604081208054349290610134908490610168565b9091555050565b5f6020828403121561014b575f80fd5b81356001600160a01b0381168114610161575f80fd5b9392505050565b8082018082111561018757634e487b7160e01b5f52601160045260245ffd5b9291505056fea26469706673582212205b3ebf660e7dcdb2d674f60a0229e4677c14be1e78d91ba988f92f12ade8038264736f6c63430008190033")]
        contract TaiyiEscrow {
            mapping(address => uint256) public balances;

            function balanceOf(address user) public view returns (uint256) {
                return balances[user];
            }

            function deposit() public payable {
                require(msg.value > 0, "Deposit amount must be greater than zero");
                balances[msg.sender] += msg.value;
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

        // Deposit into the escrow contract
        let builder = escrow.deposit().value(U256::from(100_000));
        let tx_hash = builder.send().await?.watch().await?;

        let builder = escrow.balanceOf(*sender);
        let balance = builder.call().await?._0;
        assert_eq!(balance, U256::from(100_000));

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
