
mod tests {
    use std::time::Duration;

    use alloy_consensus::{SidecarBuilder, SimpleCoder, TxEnvelope};
    use alloy_eips::{
        eip2718::Decodable2718,
        eip4844::{BYTES_PER_BLOB, DATA_GAS_PER_BLOB},
    };
    use alloy_network::{EthereumWallet, TransactionBuilder, TransactionBuilder4844};
    use alloy_node_bindings::Anvil;
    use alloy_primitives::{Address, U256};
    use alloy_provider::{Provider, ProviderBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer::Signer;
    use alloy_signer_local::PrivateKeySigner;
    use taiyi_primitives::{BlockspaceAllocation, PreconfRequestTypeB};
    use tokio::time::sleep;
    use tracing::info;
    use uuid::Uuid;

    use crate::preconf_pool::{PoolType, PreconfPoolBuilder};

    #[tokio::test]
    async fn test_add_remove_request() {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());

        let request = BlockspaceAllocation::default();
        let signature = signer.sign_hash(&request.digest()).await.unwrap();

        let mut preconf = PreconfRequestTypeB {
            allocation: request,
            alloc_sig: signature,
            transaction: None,
            signer: Some(Address::default()),
        };

        let request_id = Uuid::new_v4();
        preconf_pool._insert_pending(request_id, preconf.clone());
        assert_eq!(preconf_pool.get_pool(request_id).unwrap(), PoolType::Pending);

        // set transaction
        let raw_tx = alloy_primitives::hex::decode("02f86f0102843b9aca0085029e7822d68298f094d9e1459a7a482635700cbc20bbaf52d495ab9c9680841b55ba3ac080a0c199674fcb29f353693dd779c017823b954b3c69dffa3cd6b2a6ff7888798039a028ca912de909e7e6cdef9cdcaf24c54dd8c1032946dfa1d85c206b32a9064fe8").unwrap();
        let transaction = TxEnvelope::decode_2718(&mut raw_tx.as_slice()).unwrap();
        preconf.transaction = Some(transaction);
        preconf_pool.delete_pending(request_id);
        assert_eq!(preconf_pool.get_pending(request_id), None);

        // insert into ready pool
        preconf_pool.insert_ready(request_id, taiyi_primitives::PreconfRequest::TypeB(preconf.clone()));
        assert!(preconf_pool.get_pool(request_id).is_ok());
        assert_eq!(preconf_pool.get_pool(request_id).unwrap(), PoolType::Ready);
    }

    #[tokio::test]
    async fn test_validate() -> eyre::Result<()> {
        tracing_subscriber::fmt::init();

        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::from(10))
            .with_nonce(0)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);
        let request = BlockspaceAllocation::default();
        let signature = signer.sign_hash(&request.digest()).await.unwrap();

        let preconf_request = PreconfRequestTypeB {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction),
            signer: Some(*sender),
        };
        let validation_result = preconf_pool.validate(&preconf_request).await;
        info!("Validation result: {:?}", validation_result);

        assert!(validation_result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_validate_4844_ok() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        // Create a sidecar with some data.
        let mut builder: SidecarBuilder<SimpleCoder> = SidecarBuilder::with_capacity(3);
        let data = vec![1u8; BYTES_PER_BLOB];
        builder.ingest(&data);
        builder.ingest(&data);
        let sidecar = builder.build()?;
        assert_eq!(sidecar.blobs.len(), 3);

        let gas_price = provider.get_gas_price().await?;

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_nonce(0)
            .with_to(*receiver)
            .with_gas_limit(3 * DATA_GAS_PER_BLOB)
            .with_max_fee_per_blob_gas(gas_price)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .with_blob_sidecar(sidecar)
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);

        let request = BlockspaceAllocation { blob_count: 3, ..Default::default() };
        let signature = signer.sign_hash(&request.digest()).await.unwrap();

        let preconf_request = PreconfRequestTypeB {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction.clone()),
            signer: Some(*sender),
        };
        let validation_result = preconf_pool.validate(&preconf_request).await;
        info!("Validation result: {:?}", validation_result);

        assert!(validation_result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_validate_4844_err_esceed_blob_count_limit() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        // Create a sidecar with some data.
        let mut builder: SidecarBuilder<SimpleCoder> = SidecarBuilder::with_capacity(3);
        let data = vec![1u8; BYTES_PER_BLOB];
        builder.ingest(&data);
        builder.ingest(&data);
        let sidecar = builder.build()?;
        assert_eq!(sidecar.blobs.len(), 3);

        let gas_price = provider.get_gas_price().await?;

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_nonce(0)
            .with_to(*receiver)
            .with_gas_limit(3 * DATA_GAS_PER_BLOB)
            .with_max_fee_per_blob_gas(gas_price)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .with_blob_sidecar(sidecar.clone())
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);

        let request = BlockspaceAllocation { blob_count: 1, ..Default::default() };
        let signature = signer.sign_hash(&request.digest()).await.unwrap();

        let preconf_request = PreconfRequestTypeB {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction.clone()),
            signer: Some(*sender),
        };
        let validation_result = preconf_pool.validate(&preconf_request).await;
        info!("Validation result: {:?}", validation_result);

        assert!(validation_result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_low_balance_err() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::MAX)
            .with_nonce(0)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);

        let request = BlockspaceAllocation::default();
        let signature = signer.sign_hash(&request.digest()).await.unwrap();
        let preconf_request = PreconfRequestTypeB {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction.clone()),
            signer: Some(*sender),
        };
        let validation_result = preconf_pool.validate(&preconf_request).await;
        assert!(validation_result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_nonce_too_high() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::from(100))
            .with_nonce(5)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);

        let request = BlockspaceAllocation::default();
        let signature = signer.sign_hash(&request.digest()).await.unwrap();

        let preconf_request = PreconfRequestTypeB {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction.clone()),
            signer: Some(*sender),
        };

        let validation_result = preconf_pool.validate(&preconf_request).await;
        assert!(validation_result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_nonce_too_low() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::from(10))
            .with_nonce(0)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0);
        let pending_tx = provider.send_transaction(transaction).await?;
        info!("Pending transaction... {}", pending_tx.tx_hash());

        // Wait for the transaction to be included and get the receipt.
        let receipt = pending_tx.get_receipt().await?;

        info!(
            "Transaction included in block {}",
            receipt.block_number.expect("Failed to get block number")
        );
        // wait for 2*block_time duration
        sleep(Duration::from_secs(2)).await;

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::from(100))
            .with_nonce(0)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);
        let request = BlockspaceAllocation::default();
        let signature = signer.sign_hash(&request.digest()).await.unwrap();
        let preconf_request = PreconfRequestTypeB {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction.clone()),
            signer: Some(*sender),
        };
        let validation_result = preconf_pool.validate(&preconf_request).await;
        assert!(validation_result.is_err());
        Ok(())
    }
}
