use alloy::primitives::{Address, B256};
use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, BitList, BitVector, FixedVector, VariableList};

use super::{
    execution_payload::ExecutionPayloadHeader,
    execution_requests::ExecutionRequests,
    kzg::KzgCommitments,
    spec::{DenebSpec, ElectraSpec, EthSpec},
    utils::*,
};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindedBeaconBlockBodyDeneb<T: EthSpec> {
    pub randao_reveal: BlsSignature,
    pub eth1_data: Eth1Data,
    pub graffiti: B256,
    pub proposer_slashings: VariableList<ProposerSlashing, T::MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashingDeneb<T>, T::MaxAttesterSlashings>,
    pub attestations: VariableList<AttestationDeneb<T>, T::MaxAttestations>,
    pub deposits: VariableList<Deposit, T::MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, T::MaxVoluntaryExits>,
    pub sync_aggregate: SyncAggregate<T>,
    pub execution_payload_header: ExecutionPayloadHeader<T>,
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, T::MaxBlsToExecutionChanges>,
    pub blob_kzg_commitments: KzgCommitments<T>,
}

impl ssz::Decode for BlindedBeaconBlockBodyDeneb<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Decode for BlindedBeaconBlockBodyDeneb<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for BlindedBeaconBlockBodyDeneb<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Encode for BlindedBeaconBlockBodyDeneb<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindedBeaconBlockBodyElectra<T: EthSpec> {
    pub randao_reveal: BlsSignature,
    pub eth1_data: Eth1Data,
    pub graffiti: B256,
    pub proposer_slashings: VariableList<ProposerSlashing, T::MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashingElectra<T>, T::MaxAttesterSlashings>,
    pub attestations: VariableList<AttestationElectra<T>, T::MaxAttestations>,
    pub deposits: VariableList<Deposit, T::MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, T::MaxVoluntaryExits>,
    pub sync_aggregate: SyncAggregate<T>,
    pub execution_payload_header: ExecutionPayloadHeader<T>,
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, T::MaxBlsToExecutionChanges>,
    pub blob_kzg_commitments: KzgCommitments<T>,
    pub execution_requests: ExecutionRequests<T>,
}

impl ssz::Decode for BlindedBeaconBlockBodyElectra<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Decode for BlindedBeaconBlockBodyElectra<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for BlindedBeaconBlockBodyElectra<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Encode for BlindedBeaconBlockBodyElectra<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Eth1Data {
    pub deposit_root: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_count: u64,
    pub block_hash: B256,
}

impl ssz::Decode for Eth1Data {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for Eth1Data {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

impl ssz::Decode for BeaconBlockHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for BeaconBlockHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: BlsSignature,
}

impl ssz::Decode for SignedBeaconBlockHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for SignedBeaconBlockHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BlsToExecutionChange {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub from_bls_pubkey: BlsPublicKey,
    pub to_execution_address: Address,
}

impl ssz::Decode for BlsToExecutionChange {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for BlsToExecutionChange {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignedBlsToExecutionChange {
    pub message: BlsToExecutionChange,
    pub signature: BlsSignature,
}

impl ssz::Decode for SignedBlsToExecutionChange {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for SignedBlsToExecutionChange {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttesterSlashingDeneb<T: EthSpec> {
    pub attestation_1: IndexedAttestationDeneb<T>,
    pub attestation_2: IndexedAttestationDeneb<T>,
}

impl ssz::Decode for AttesterSlashingDeneb<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Decode for AttesterSlashingDeneb<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for AttesterSlashingDeneb<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Encode for AttesterSlashingDeneb<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttesterSlashingElectra<T: EthSpec> {
    pub attestation_1: IndexedAttestationElectra<T>,
    pub attestation_2: IndexedAttestationElectra<T>,
}

impl ssz::Decode for AttesterSlashingElectra<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Decode for AttesterSlashingElectra<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for AttesterSlashingElectra<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Encode for AttesterSlashingElectra<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct IndexedAttestationDeneb<T: EthSpec> {
    /// Lists validator registry indices, not committee indices.
    #[serde(with = "quoted_variable_list_u64")]
    pub attesting_indices: VariableList<u64, T::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

impl ssz::Decode for IndexedAttestationDeneb<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Decode for IndexedAttestationDeneb<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for IndexedAttestationDeneb<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Encode for IndexedAttestationDeneb<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct IndexedAttestationElectra<T: EthSpec> {
    /// Lists validator registry indices, not committee indices.
    #[serde(with = "quoted_variable_list_u64")]
    pub attesting_indices: VariableList<u64, T::MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

impl ssz::Decode for IndexedAttestationElectra<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Decode for IndexedAttestationElectra<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for IndexedAttestationElectra<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Encode for IndexedAttestationElectra<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttestationData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    // LMD GHOST vote
    pub beacon_block_root: B256,
    // FFG Vote
    pub source: Checkpoint,
    pub target: Checkpoint,
}

impl ssz::Decode for AttestationData {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for AttestationData {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
    pub root: B256,
}

impl ssz::Decode for Checkpoint {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for Checkpoint {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct AttestationDeneb<T: EthSpec> {
    pub aggregation_bits: BitList<T::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

impl ssz::Decode for AttestationDeneb<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Decode for AttestationDeneb<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for AttestationDeneb<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Encode for AttestationDeneb<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct AttestationElectra<T: EthSpec> {
    pub aggregation_bits: BitList<T::MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: BlsSignature,
    pub committee_bits: BitVector<T::MaxCommitteesPerSlot>,
}

impl ssz::Decode for AttestationElectra<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Decode for AttestationElectra<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for AttestationElectra<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Encode for AttestationElectra<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Deposit {
    pub proof: FixedVector<B256, typenum::U33>, // put this in EthSpec?
    pub data: DepositData,
}

impl ssz::Decode for Deposit {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for Deposit {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DepositData {
    pub pubkey: BlsPublicKey,
    pub withdrawal_credentials: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: BlsSignature,
}

impl ssz::Decode for DepositData {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for DepositData {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: BlsSignature,
}

impl ssz::Decode for SignedVoluntaryExit {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for SignedVoluntaryExit {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct VoluntaryExit {
    /// Earliest epoch when voluntary exit can be processed.
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct SyncAggregate<T: EthSpec> {
    pub sync_committee_bits: BitVector<T::SyncCommitteeSize>,
    pub sync_committee_signature: BlsSignature,
}

impl ssz::Decode for SyncAggregate<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Decode for SyncAggregate<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for SyncAggregate<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Encode for SyncAggregate<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}
