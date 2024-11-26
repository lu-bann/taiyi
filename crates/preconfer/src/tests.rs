mod tests {
    #![allow(unused_variables)]

    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
    };

    use alloy_network::{EthereumWallet, TransactionBuilder};
    use alloy_node_bindings::Anvil;
    use alloy_primitives::{hex, keccak256, Address, U256};
    use alloy_provider::{Provider, ProviderBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer_local::PrivateKeySigner;
    use ethereum_consensus::deneb::Context;
    use k256::{ecdsa::VerifyingKey, Secp256k1};
    use reqwest::Url;
    use secp256k1::{ecdsa::Signature as EcdsaSignature, Message, PublicKey as EcdsaPublicKey};
    use taiyi_primitives::{BlockspaceAllocation, PreconfRequest, PreconfResponse};
    use tracing::info;

    use crate::{
        clients::{relay_client::RelayClient, signer_client::SignerClient},
        network_state::NetworkState,
        preconf_api::{
            api::{PreconfApiServer, PRECONF_REQUEST_PATH},
            state::PreconfState,
        },
    };

    #[tokio::test]
    async fn spawn_preconf_api_server() -> eyre::Result<()> {
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

        let state =
            PreconfState::new(network_state, relay_client, signer_client.clone(), rpc_url.clone());

        let preconfapiserver =
            PreconfApiServer::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5656));
        let server_endpoint = preconfapiserver.endpoint();
        let _ = preconfapiserver.run(state.clone()).await;

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer);

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

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

        info!("Transaction built: {:?}", transaction);

        let preconf_request = PreconfRequest {
            allocation: BlockspaceAllocation::default(),
            transaction: Some(transaction),
            target_slot: 5,
        };
        let request_endpoint =
            Url::parse(&server_endpoint).unwrap().join(PRECONF_REQUEST_PATH).unwrap();
        let response =
            reqwest::Client::new().post(request_endpoint).json(&preconf_request).send().await?;

        assert_eq!(response.status(), 200);
        let preconf_response: PreconfResponse = response.json().await?;

        let message = {
            let mut data = Vec::new();
            data.extend_from_slice(
                preconf_request.transaction.expect("preconf tx not found").tx_hash().as_slice(),
            );
            data.extend_from_slice(&preconf_request.target_slot.to_le_bytes());
            keccak256(data)
        };

        let commitment = preconf_response.data.commitment.unwrap();

        // TODO: fix signature verification

        // let ecda_sig = EcdsaSignature::from_compact(&commitment.as_bytes())?;

        // let message = Message::from_digest(*message);
        // let is_valid = ecda_sig.verify(&message, &EcdsaPublicKey::from_str(&ecdsa_pubkey)?).is_ok();
        // assert!(is_valid);

        Ok(())
    }
}
