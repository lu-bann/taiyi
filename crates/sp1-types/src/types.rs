use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{hex, keccak256, Address, Bytes, PrimitiveSignature, TxHash, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct PreconfRequestTypeA {
    pub tip_transaction: TxEnvelope,
    pub transactions: Vec<TxEnvelope>,
    pub target_slot: u64,
    pub sequence_number: Option<u64>,
    pub signer: Address,
    pub preconf_sig: PrimitiveSignature,
}

impl PreconfRequestTypeA {
    pub fn digest(&self, chain_id: u64) -> B256 {
        let mut preconf_txs: Vec<String> = Vec::new();
        for tx in &self.transactions {
            let mut tx_bytes = Vec::new();
            tx.encode_2718(&mut tx_bytes);
            let hex_encoded_tx = format!("0x{}", hex::encode(&tx_bytes));
            preconf_txs.push(hex_encoded_tx);
        }

        let mut tip_tx = Vec::new();
        self.tip_transaction.encode_2718(&mut tip_tx);
        let tip_tx_raw = format!("0x{}", hex::encode(&tip_tx));
        let sequence_number = self.sequence_number.expect("Sequence number should be present");

        keccak256(
            (
                tip_tx_raw.as_bytes(),
                preconf_txs.iter().map(|s| s.as_bytes()).collect::<Vec<_>>(),
                self.target_slot,
                sequence_number,
                self.signer,
                chain_id,
            )
                .abi_encode_packed(),
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BlockspaceAllocation {
    pub gas_limit: u64,
    pub sender: Address,
    pub recipient: Address,
    pub deposit: U256,
    pub tip: U256,
    pub target_slot: u64,
    pub blob_count: usize,
}

impl BlockspaceAllocation {
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

#[derive(Serialize, Deserialize, Clone)]
pub struct PreconfRequestTypeB {
    pub allocation: BlockspaceAllocation,
    pub alloc_sig: PrimitiveSignature,
    pub transaction: Option<TxEnvelope>,
    pub preconf_sig: PrimitiveSignature,
}

impl PreconfRequestTypeB {
    pub fn digest(&self, chain_id: u64) -> B256 {
        let mut tx_bytes = Vec::new();
        self.transaction.clone().expect("Tx should be present").encode_2718(&mut tx_bytes);
        let raw_tx = format!("0x{}", hex::encode(&tx_bytes));
        keccak256((self.allocation.hash(chain_id), raw_tx.as_bytes()).abi_encode_packed())
    }
}

#[derive(Serialize, Deserialize)]
pub struct TxMerkleProof {
    pub key: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
    pub root: B256,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AccountMerkleProof {
    pub address: Address,
    pub nonce: u64,
    pub balance: U256,
    pub storage_hash: B256,
    pub code_hash: B256,
    pub account_proof: Vec<Bytes>,
    pub state_root: B256,
}

#[derive(Serialize, Deserialize)]
pub struct PreconfTypeA {
    pub preconf: PreconfRequestTypeA,
    pub anchor_tx: TxEnvelope,
    pub tx_merkle_proof: Vec<TxMerkleProof>, /* Inclusion proofs of the user transaction and anchor tx in the block */
    pub account_merkle_proof: Vec<AccountMerkleProof>, /* Merkle proofs of the account states (user's) */
}

#[derive(Serialize, Deserialize)]
pub struct PreconfTypeB {
    pub preconf: PreconfRequestTypeB,
    pub sponsorship_tx: TxEnvelope,
    pub tx_merkle_proof: Vec<TxMerkleProof>, /* Inclusion proofs of the user transaction and sponsorship tx in the block */
    pub account_merkle_proof: AccountMerkleProof, // Merkle proof of the account state (user's)
}

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("Leaves and indices length mismatch")]
    LengthMismatch,
    #[error("Mismatch in provided leaves and leaves to prove")]
    LeavesMismatch,
    #[error("Hash not found in constraints cache: {0:?}")]
    MissingHash(TxHash),
    #[error("Proof verification failed")]
    VerificationFailed,
}
