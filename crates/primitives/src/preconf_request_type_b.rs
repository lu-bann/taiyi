use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{hex, keccak256, Address, PrimitiveSignature, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::PreconfFeeResponse;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfRequestTypeB {
    /// blockspace allocated
    pub allocation: BlockspaceAllocation,
    /// Signature by the user over allocation
    pub alloc_sig: PrimitiveSignature,
    /// Preconf transaction
    pub transaction: Option<TxEnvelope>,
    /// The signer of the request
    pub signer: Address,
}

impl PreconfRequestTypeB {
    /// Returns the request signer.
    pub fn signer(&self) -> Address {
        self.signer
    }

    /// Sets the signer.
    pub fn set_signer(&mut self, signer: Address) {
        self.signer = signer;
    }

    /// Set alloc signature
    pub fn set_alloc_sig(&mut self, sig: PrimitiveSignature) {
        self.alloc_sig = sig;
    }

    /// Target slot
    pub fn target_slot(&self) -> u64 {
        self.allocation.target_slot
    }

    /// preconf tip
    pub fn preconf_tip(&self) -> U256 {
        self.allocation.preconf_tip()
    }

    /// Digest over allocation and transaction
    pub fn digest(&self, chain_id: u64) -> B256 {
        let mut tx_bytes = Vec::new();
        self.transaction.clone().expect("Tx should be present").encode_2718(&mut tx_bytes);
        let raw_tx = format!("0x{}", hex::encode(&tx_bytes));
        keccak256((self.allocation.hash(chain_id), raw_tx.as_bytes()).abi_encode_packed())
    }
}

/// Amount of blockspace to be allocated
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct BlockspaceAllocation {
    /// The gas limit for the block
    /// This is the maximum amount of gas that can be used in the block
    pub gas_limit: u64,
    /// The address initiating the preconfirmation request
    pub sender: Address,
    /// The address receiving the preconfirmation tip
    pub recipient: Address,
    /// The deposit to be paid for the blockspace allocation.
    /// This is the amount deducted from the user's escrow balance when the user fails to submit a transaction
    /// for the allocated blockspace.
    ///
    /// The deposit is calculated as follows:
    /// { gas_limit * gas_fee + blob_count * DATA_GAS_PER_BLOB * blob_gas_fee } * 0.5
    pub deposit: U256,
    /// This is the amount deducted from the user's escrow balance along with `[deposit]` when the user
    /// submits a transaction for the allocated blockspace.
    ///
    /// The tip is calculated as follows:
    /// { gas_limit * gas_fee + blob_count * DATA_GAS_PER_BLOB * blob_gas_fee } * 0.5
    pub tip: U256,
    /// The slot to reserve blockspace for
    pub target_slot: u64,
    /// Number of blobs to reserve
    pub blob_count: usize,
    /// Gas fees quoted by the underwriter for the transaction
    pub preconf_fee: PreconfFeeResponse,
}

impl BlockspaceAllocation {
    pub fn preconf_tip(&self) -> U256 {
        self.tip + self.deposit
    }

    pub fn struct_hash(&self) -> B256 {
        keccak256(
            (
                blockspace_allocation_type_hash(),
                self.gas_limit,
                self.sender,
                self.recipient,
                self.deposit,
                self.tip,
                self.target_slot,
                self.blob_count as u64,
            )
                .abi_encode(),
        )
    }

    pub fn hash(&self, chain_id: u64) -> B256 {
        keccak256(("\x19\x01", domain_separator(chain_id), self.struct_hash()).abi_encode_packed())
    }
}

pub fn eip712_domain_type_hash() -> B256 {
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
}

pub fn blockspace_allocation_type_hash() -> B256 {
    keccak256("BlockspaceAllocation(uint256 gasLimit,address sender,address recipient,uint256 deposit,uint256 tip,uint256 targetSlot,uint256 blobCount)")
}

pub fn domain_separator(chain_id: u64) -> B256 {
    let type_hash = eip712_domain_type_hash();
    let contract_name = keccak256("TaiyiCore".as_bytes());
    let version = keccak256("1.0".as_bytes());
    keccak256((type_hash, contract_name, version, chain_id).abi_encode())
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SubmitTransactionRequest {
    pub request_id: Uuid,
    pub transaction: TxEnvelope,
}

impl SubmitTransactionRequest {
    pub fn new(request_id: Uuid, transaction: TxEnvelope) -> Self {
        Self { request_id, transaction }
    }

    pub fn digest(&self) -> B256 {
        let mut digest = Vec::new();
        digest.extend_from_slice(&self.request_id.to_bytes_le());
        digest.extend_from_slice(self.transaction.tx_hash().as_slice());
        keccak256(&digest)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use alloy_provider::network::{EthereumWallet, TransactionBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer_local::PrivateKeySigner;

    #[tokio::test]
    async fn test_set_signer() -> eyre::Result<()> {
        let signer = PrivateKeySigner::random();
        let mut request = PreconfRequestTypeB {
            allocation: BlockspaceAllocation {
                sender: signer.address(),
                recipient: signer.address(), // dont care about recipient in this test
                gas_limit: 21_000,
                deposit: U256::from(1000),
                tip: U256::from(1000),
                target_slot: 1234,
                blob_count: 0,
                preconf_fee: PreconfFeeResponse { gas_fee: 2, blob_gas_fee: 3 },
            },
            alloc_sig: PrimitiveSignature::from_raw(
                // random 65 bytes
                &hex::decode("0x".to_owned() + &"a".repeat(130))?,
            )
            .unwrap(),
            transaction: None,
            signer: signer.address(),
        };
        {
            let new_signer = PrivateKeySigner::random();
            request.set_signer(new_signer.address());
            assert_eq!(request.signer(), new_signer.address());
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_transaction_request() -> eyre::Result<()> {
        let signer = PrivateKeySigner::random();
        let tx = {
            let signer = signer.clone();

            let chain_id = 123;
            let sender = signer.address();
            let wallet = EthereumWallet::from(signer);
            let nonce = 1234;
            TransactionRequest::default()
                .with_from(sender)
                .with_value(U256::from(1000))
                .with_nonce(nonce)
                .with_gas_limit(21_000)
                .with_to(sender)
                .with_max_fee_per_gas(2)
                .with_max_priority_fee_per_gas(3)
                .with_chain_id(chain_id)
                .build(&wallet)
                .await?
        };
        let tx_uuid = Uuid::new_v4();
        let request = SubmitTransactionRequest { transaction: tx.clone(), request_id: tx_uuid };
        assert_eq!(SubmitTransactionRequest::new(tx_uuid, tx), request);
        Ok(())
    }
}
