use alloy_eips::eip4844::{
    builder::{SidecarBuilder, SimpleCoder},
    DATA_GAS_PER_BLOB,
};
use alloy_primitives::{Address, U256};
use alloy_provider::network::{EthereumWallet, TransactionBuilder, TransactionBuilder4844};
use alloy_rpc_types::TransactionRequest;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use reqwest::Url;
use taiyi_primitives::{
    BlockspaceAllocation, PreconfFeeResponse, PreconfResponseData, SlotInfo,
    SubmitTransactionRequest, SubmitTypeATransactionRequest,
};
use taiyi_underwriter::{
    AVAILABLE_SLOT_PATH, PRECONF_FEE_PATH, RESERVE_BLOCKSPACE_PATH, SUBMIT_TRANSACTION_PATH,
    SUBMIT_TYPEA_TRANSACTION_PATH,
};
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub struct HttpClient {
    http: reqwest::Client,
    endpoint: Url,
    signer: PrivateKeySigner,
    wallet: EthereumWallet,
    chain_id: u64,
}

impl HttpClient {
    pub fn new(endpoint: Url, signer: PrivateKeySigner, chain_id: u64) -> Self {
        let wallet = EthereumWallet::from(signer.clone());
        Self { http: reqwest::Client::new(), endpoint, signer, wallet, chain_id }
    }

    pub async fn slots(&self) -> eyre::Result<Vec<SlotInfo>> {
        let target = self.endpoint.join(AVAILABLE_SLOT_PATH)?;
        let result: Vec<SlotInfo> = self.http.get(target).send().await?.json().await?;
        Ok(result)
    }

    pub async fn preconf_fee(&self, slot: u64) -> eyre::Result<PreconfFeeResponse> {
        let target = self.endpoint.join(PRECONF_FEE_PATH)?;
        let response = self.http.post(target).json(&slot).send().await?;
        let bytes = response.bytes().await?;
        let preconf_fee: PreconfFeeResponse = serde_json::from_slice(&bytes)?;
        Ok(preconf_fee)
    }

    pub async fn reserve_blockspace(&self, slot: u64, recipient: Address) -> eyre::Result<Uuid> {
        let preconf_fee = self.preconf_fee(slot).await?;

        let gas_limit = 21_000;
        let blob_count = 1;

        // let gas_limit = 1_000_000;
        // let blob_count = 2;
        let fee = preconf_fee.gas_fee * (gas_limit as u128)
            + preconf_fee.blob_gas_fee * ((blob_count * DATA_GAS_PER_BLOB) as u128);
        let fee = U256::from(fee / 2);

        let blockspace_data = BlockspaceAllocation {
            target_slot: slot,
            sender: self.signer.address(),
            recipient: recipient,
            deposit: fee,
            tip: fee,
            gas_limit,
            blob_count: blob_count.try_into().unwrap(),
            preconf_fee,
        };
        let signature = hex::encode(
            self.signer.sign_hash(&blockspace_data.hash(self.chain_id)).await.unwrap().as_bytes(),
        );
        let target = self.endpoint.join(RESERVE_BLOCKSPACE_PATH)?;
        let result = self
            .http
            .post(target)
            .header("content-type", "application/json")
            .header("x-luban-signature", format!("0x{signature}"))
            .json(&blockspace_data)
            .send()
            .await?;
        let bytes = result.bytes().await?;
        info!("Reserve Blockspace Response: {:?}", bytes);
        let request_id: Uuid = serde_json::from_slice(&bytes)?;
        Ok(request_id)
    }

    pub async fn submit_transaction_type_b(
        &self,
        request_id: Uuid,
        nonce: u64,
        chain_id: u64,
    ) -> eyre::Result<PreconfResponseData> {
        let target = self.endpoint.join(SUBMIT_TRANSACTION_PATH)?;

        let eth_transfer_tx = TransactionRequest::default()
            .with_from(self.signer.address())
            .with_chain_id(chain_id)
            .with_value(U256::from(1000))
            .with_gas_limit(21_000)
            .with_to(self.signer.address())
            .with_max_fee_per_gas(1000000010)
            .with_max_priority_fee_per_gas(1000000000)
            .with_nonce(nonce)
            .build(&self.wallet)
            .await?;

        let tx_hash = eth_transfer_tx.tx_hash();
        info!("Transaction Hash: {:?}", tx_hash);

        let request = SubmitTransactionRequest { request_id, transaction: eth_transfer_tx };
        let signature =
            hex::encode(self.signer.sign_hash(&request.digest()).await.unwrap().as_bytes());

        let result = self
            .http
            .post(target)
            .header("content-type", "application/json")
            .header("x-luban-signature", format!("0x{signature}"))
            .json(&request)
            .send()
            .await?;
        let bytes = result.bytes().await?;
        info!("Submit Transaction Response: {:?}", bytes);
        let response: PreconfResponseData = serde_json::from_slice(&bytes)?;
        Ok(response)
    }

    pub async fn submit_blob_transaction(
        &self,
        request_id: Uuid,
        nonce: u64,
        chain_id: u64,
    ) -> eyre::Result<PreconfResponseData> {
        let target = self.endpoint.join(SUBMIT_TRANSACTION_PATH)?;
        // Create a sidecar with some data.
        let builder: SidecarBuilder<SimpleCoder> = SidecarBuilder::with_capacity(3);
        // let data = vec![1u8; BYTES_PER_BLOB];
        // builder.ingest(&data);
        // builder.ingest(&data);
        let sidecar = builder.build()?;
        assert_eq!(sidecar.blobs.len(), 1);

        let blob_transaction = TransactionRequest::default()
            .with_from(self.signer.address())
            .with_nonce(nonce)
            .with_to(self.signer.address())
            .with_gas_limit(3 * DATA_GAS_PER_BLOB)
            .with_max_fee_per_blob_gas(1000000000)
            .with_max_fee_per_gas(1000000010)
            .with_max_priority_fee_per_gas(1000000000)
            .with_chain_id(chain_id)
            .with_blob_sidecar(sidecar)
            .build(&self.wallet)
            .await?;

        let tx_hash = blob_transaction.tx_hash();
        info!("Transaction Hash: {:?}", tx_hash);

        let request = SubmitTransactionRequest { request_id, transaction: blob_transaction };
        let signature =
            hex::encode(self.signer.sign_hash(&request.digest()).await.unwrap().as_bytes());

        let result = self
            .http
            .post(target)
            .header("content-type", "application/json")
            .header("x-luban-signature", format!("0x{signature}"))
            .json(&request)
            .send()
            .await?;
        let bytes = result.bytes().await?;
        info!("Submit Blob Transaction Response: {:?}", bytes);
        let response: PreconfResponseData = serde_json::from_slice(&bytes)?;
        Ok(response)
    }

    pub async fn submit_type_a_request(
        &self,
        slot: u64,
        nonce: u64,
        chain_id: u64,
    ) -> eyre::Result<PreconfResponseData> {
        let preconf_fee = self.preconf_fee(slot).await?;
        let tip_transaction = TransactionRequest::default()
            .with_from(self.signer.address())
            .with_value(U256::from(preconf_fee.gas_fee * 21_000 * 2))
            .with_nonce(nonce)
            .with_gas_limit(21_000)
            .with_to(self.signer.address())
            .with_max_fee_per_gas(1000000010)
            .with_max_priority_fee_per_gas(1000000000)
            .with_chain_id(chain_id)
            .build(&self.wallet)
            .await?;

        let preconf_transaction = TransactionRequest::default()
            .with_from(self.signer.address())
            .with_value(U256::from(preconf_fee.gas_fee * 21_000 * 2))
            .with_nonce(nonce + 1)
            .with_gas_limit(21_000)
            .with_to(self.signer.address())
            .with_max_fee_per_gas(1000000010)
            .with_max_priority_fee_per_gas(1000000000)
            .with_chain_id(chain_id)
            .build(&self.wallet)
            .await?;

        info!("Tip Transaction Hash: {:?}", tip_transaction.tx_hash());
        info!("Preconf Transaction Hash: {:?}", preconf_transaction.tx_hash());

        let request =
            SubmitTypeATransactionRequest::new(vec![preconf_transaction], tip_transaction, slot);
        let signature =
            hex::encode(self.signer.sign_hash(&request.digest()).await.unwrap().as_bytes());

        let target = self.endpoint.join(SUBMIT_TYPEA_TRANSACTION_PATH)?;
        let result = self
            .http
            .post(target)
            .header("content-type", "application/json")
            .header("x-luban-signature", format!("0x{signature}"))
            .json(&request)
            .send()
            .await?;
        let body = result.text().await?;
        info!("Submit Transaction Response: {:?}", body);
        let response: PreconfResponseData = serde_json::from_str(&body)?;
        Ok(response)
    }
}
