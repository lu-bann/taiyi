use std::collections::{hash_map::Entry, HashMap};

use alloy_consensus::transaction::Transaction;
use alloy_primitives::Address;
use taiyi_primitives::{
    PreconfFeeResponse, PreconfRequest, PreconfRequestTypeA, SubmitTypeATransactionRequest,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    api::PreconfApiResult,
    block_info::{BlockInfo, BlockInfoError},
    broadcast_sender::Sender,
    sequence_number::SequenceNumberPerSlot,
};

#[derive(Debug, Error, PartialEq)]
pub enum UnderwriterError {
    #[error("{0}")]
    BlockInfo(#[from] BlockInfoError),

    #[error("No reserved transaction for {id}")]
    MissingTransaction { id: Uuid },
}

#[derive(Debug)]
pub struct Underwriter {
    reference_block_info: BlockInfo,
    block_info: HashMap<u64, (BlockInfo, Vec<Uuid>)>,
    sequence_number_per_slot: SequenceNumberPerSlot,
}

pub type UnderwriterResult<T> = Result<T, UnderwriterError>;

impl Underwriter {
    pub fn new(reference_block_info: BlockInfo) -> Self {
        Self {
            reference_block_info,
            block_info: HashMap::new(),
            sequence_number_per_slot: SequenceNumberPerSlot::default(),
        }
    }

    pub fn get_block_info(&mut self, slot: u64) -> &mut (BlockInfo, Vec<Uuid>) {
        if let Entry::Vacant(e) = self.block_info.entry(slot) {
            e.insert((self.reference_block_info, vec![]));
        }
        self.block_info.get_mut(&slot).expect("Must be available")
    }

    pub fn reserve_blockspace(
        &mut self,
        slot: u64,
        gas: u64,
        blobs: usize,
    ) -> Result<(), BlockInfoError> {
        self.get_block_info(slot).0.update(gas, blobs, 1)
    }

    pub fn remove_slots_until(&mut self, slot: &u64) {
        self.block_info.retain(|reserved_slot, _| reserved_slot > slot);
    }

    pub async fn reserve_slot_with_calldata<S: Sender>(
        &mut self,
        id: Uuid,
        request: SubmitTypeATransactionRequest,
        preconf_fee: PreconfFeeResponse,
        sender: S,
        signer: Address,
    ) -> PreconfApiResult<()> {
        let sequence_number = Some(self.sequence_number_per_slot.get_next(request.target_slot));
        let preconf_request = PreconfRequestTypeA {
            preconf_tx: request.clone().preconf_transaction,
            tip_transaction: request.clone().tip_transaction,
            target_slot: request.target_slot,
            sequence_number,
            signer,
            preconf_fee: preconf_fee.clone(),
        };

        let required_gas = get_required_gas(&preconf_request);
        let required_blobs = get_required_blobs(&preconf_request);
        self.get_block_info(request.target_slot).0.update(required_gas, required_blobs, 1)?;
        self.sequence_number_per_slot
            .add(request.target_slot, request.preconf_transaction.len() as u64 + 1);

        sender.sign_and_send(id, PreconfRequest::TypeA(preconf_request)).await?;

        Ok(())
    }
}

pub fn get_required_gas(request: &PreconfRequestTypeA) -> u64 {
    request.tip_transaction.gas_limit()
        + request.preconf_tx.iter().map(|tx| tx.gas_limit()).sum::<u64>()
}

pub fn get_required_blobs(request: &PreconfRequestTypeA) -> usize {
    request
        .preconf_tx
        .iter()
        .filter(|tx| tx.is_eip4844())
        .map(|tx| {
            tx.as_eip4844()
                .expect("No eip4844 transaction")
                .tx()
                .blob_versioned_hashes()
                .iter()
                .len()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broadcast_sender::MockSender;
    use alloy_consensus::{TxEip1559, TxEnvelope};
    use alloy_primitives::{Signature, U256};

    #[test]
    fn test_reserve_blockspace_works_for_new_slot_within_limits() {
        let gas_limit = 123456;
        let blob_limit = 1324;
        let constraint_limit = 12;
        let reference_block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);
        let mut underwriter = Underwriter::new(reference_block_info);

        let target_slot = 234;
        let gas = 100;
        let blobs = 3;
        assert!(underwriter.reserve_blockspace(target_slot, gas, blobs).is_ok());
    }

    #[test]
    fn test_reserve_blockspace_fails_for_new_slot_that_exceeds_limits() {
        let gas_limit = 123456;
        let blob_limit = 1324;
        let constraint_limit = 12;
        let reference_block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);
        let mut underwriter = Underwriter::new(reference_block_info);

        let target_slot = 234;
        let gas = 123457;
        let blobs = 3;
        let err = underwriter.reserve_blockspace(target_slot, gas, blobs).unwrap_err();
        assert_eq!(err, BlockInfoError::GasLimit { available: gas_limit, required: gas });
    }

    #[test]
    fn test_reserve_blockspace_with_two_slots() {
        let gas_limit = 123456;
        let blob_limit = 1324;
        let constraint_limit = 12;
        let reference_block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);
        let mut underwriter = Underwriter::new(reference_block_info);

        let target_slot_1 = 234;
        let target_slot_2 = 24;
        let gas = 100;
        let blobs = 3;
        assert!(underwriter.reserve_blockspace(target_slot_1, gas, blobs).is_ok());
        assert!(underwriter.reserve_blockspace(target_slot_1, gas, blobs).is_ok());
        assert!(underwriter.reserve_blockspace(target_slot_2, gas, blobs).is_ok());

        let gas = 123406;
        let err = underwriter.reserve_blockspace(target_slot_1, gas, blobs).unwrap_err();
        assert_eq!(err, BlockInfoError::GasLimit { available: 123256, required: gas });
    }

    #[test]
    fn test_remove_old_slots() {
        let gas_limit = 123456;
        let blob_limit = 1324;
        let constraint_limit = 12;
        let reference_block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);
        let mut underwriter = Underwriter::new(reference_block_info);

        let target_slot_1 = 234;
        let target_slot_2 = 24;
        let gas = 100;
        let blobs = 3;
        assert!(underwriter.reserve_blockspace(target_slot_1, gas, blobs).is_ok());
        assert!(underwriter.reserve_blockspace(target_slot_1, gas, blobs).is_ok());
        assert!(underwriter.reserve_blockspace(target_slot_2, gas, blobs).is_ok());

        let last_slot = 25;
        underwriter.remove_slots_until(&last_slot);
        let gas = 123406;
        let err = underwriter.reserve_blockspace(target_slot_1, gas, blobs).unwrap_err();
        assert_eq!(err, BlockInfoError::GasLimit { available: 123256, required: gas });
        assert!(underwriter.reserve_blockspace(target_slot_2, gas_limit, blobs).is_ok());
        let err = underwriter.reserve_blockspace(target_slot_2, gas_limit, blobs).unwrap_err();
        assert_eq!(err, BlockInfoError::GasLimit { available: 0, required: gas_limit })
    }

    fn get_test_signature() -> Signature {
        Signature::new(U256::ONE, U256::default(), false)
    }

    fn get_test_transaction() -> TxEnvelope {
        TxEnvelope::new_unhashed(TxEip1559::default().into(), get_test_signature())
    }

    #[tokio::test]
    async fn test_reserve_slot_with_calldata() {
        let gas_limit = 123456;
        let blob_limit = 1324;
        let constraint_limit = 12;
        let reference_block_info = BlockInfo::new(gas_limit, blob_limit, constraint_limit);
        let mut underwriter = Underwriter::new(reference_block_info);

        let preconf_fee = PreconfFeeResponse { gas_fee: 10, blob_gas_fee: 150 };
        let request = SubmitTypeATransactionRequest {
            tip_transaction: get_test_transaction(),
            preconf_transaction: vec![],
            target_slot: 10,
        };
        let signer = Address::random();
        let mut sender = MockSender::new();
        sender
            .expect_sign_and_send()
            .withf(|_, request| match request {
                PreconfRequest::TypeA(request) => request.sequence_number == Some(1u64),
                PreconfRequest::TypeB(_) => false,
            })
            .return_once(|_, _| Box::pin(async { Ok(()) }));
        let id = Uuid::new_v4();
        assert!(underwriter
            .reserve_slot_with_calldata(id, request, preconf_fee, sender, signer,)
            .await
            .is_ok());
    }
}
