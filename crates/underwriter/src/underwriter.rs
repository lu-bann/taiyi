use std::sync::Arc;

use alloy::consensus::transaction::Transaction;
use alloy::primitives::{Address, U256};
use taiyi_primitives::encode_util::hex_encode;
use taiyi_primitives::PreconfResponseData;
use taiyi_primitives::{
    slot_info::{SlotInfo, SlotInfoError},
    PreconfFee, PreconfRequest, PreconfRequestTypeA, SubmitTypeATransactionRequest,
};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::preconf_signer::PreconfSigner;
use crate::{
    api::PreconfApiResult, broadcast_sender::Sender, sequence_number::SequenceNumberPerSlot,
};

#[derive(Debug, Error, PartialEq)]
pub enum UnderwriterError {
    #[error("{0}")]
    SlotInfo(#[from] SlotInfoError),

    #[error("No reserved transaction for {id}")]
    MissingTransaction { id: Uuid },

    #[error("Slot {slot} is not available")]
    SlotNotAvailable { slot: u64 },

    #[error("Insufficient tip (expected={expected}, tip={tip})")]
    InsufficientTip { tip: U256, expected: U256 },
}

pub fn verify_tip(tip: U256, expected: U256) -> Result<(), UnderwriterError> {
    if tip < expected {
        return Err(UnderwriterError::InsufficientTip { expected, tip });
    }
    Ok(())
}

#[derive(Debug)]
pub struct Underwriter {
    slot_infos: Arc<RwLock<Vec<SlotInfo>>>,
    sequence_number_per_slot: SequenceNumberPerSlot,
}

pub type UnderwriterResult<T> = Result<T, UnderwriterError>;

impl Underwriter {
    pub fn new(slot_infos: Arc<RwLock<Vec<SlotInfo>>>) -> Self {
        Self { slot_infos, sequence_number_per_slot: SequenceNumberPerSlot::default() }
    }

    pub async fn reserve_blockspace(
        &mut self,
        slot: u64,
        gas: u64,
        blobs: usize,
    ) -> UnderwriterResult<()> {
        Ok(self
            .slot_infos
            .write()
            .await
            .iter_mut()
            .find(|info| info.slot == slot)
            .ok_or(UnderwriterError::SlotNotAvailable { slot })?
            .update(gas, blobs, 1)?)
    }

    pub async fn reserve_slot_with_calldata<S: Sender, Signer: PreconfSigner>(
        &mut self,
        id: Uuid,
        request: SubmitTypeATransactionRequest,
        preconf_fee: PreconfFee,
        sender: S,
        signer: Signer,
        preconf_sender: Address,
        last_slot: u64,
    ) -> PreconfApiResult<PreconfResponseData> {
        let sequence_number = Some(self.sequence_number_per_slot.get_next(request.target_slot));
        let preconf_request = PreconfRequestTypeA {
            preconf_tx: request.clone().preconf_transaction,
            tip_transaction: request.clone().tip_transaction,
            target_slot: request.target_slot,
            sequence_number,
            signer: preconf_sender,
            preconf_fee: preconf_fee.clone(),
        };

        let required_gas = get_required_gas(&preconf_request);
        let required_blobs = get_required_blobs(&preconf_request);
        let expected_tip = preconf_fee.compute_tip(required_gas, required_blobs);
        verify_tip(preconf_request.preconf_tip(), expected_tip)?;
        self.reserve_blockspace(request.target_slot, required_gas, required_blobs).await?;
        self.sequence_number_per_slot
            .add(request.target_slot, request.preconf_transaction.len() as u64 + 1);
        let signature = signer.sign(PreconfRequest::TypeA(preconf_request.clone())).await?;
        let response = PreconfResponseData {
            request_id: id,
            commitment: Some(hex_encode(signature.as_bytes())),
            sequence_num: sequence_number,
            current_slot: last_slot,
        };
        sender.send(PreconfRequest::TypeA(preconf_request), response.clone()).await?;

        Ok(response)
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
    use alloy::consensus::{TxEip1559, TxEnvelope};
    use alloy::primitives::{Signature, U256};

    #[tokio::test]
    async fn test_reserve_blockspace_fails_if_no_slot_is_available() {
        let slot_infos = Arc::new(RwLock::new(vec![]));
        let mut underwriter = Underwriter::new(slot_infos);

        let target_slot = 234;
        let gas = 100;
        let blobs = 3;
        let err = underwriter.reserve_blockspace(target_slot, gas, blobs).await.unwrap_err();
        assert_eq!(err, UnderwriterError::SlotNotAvailable { slot: target_slot });
    }

    const DUMMY_GAS_AVAILABLE: u64 = 123456;
    const DUMMY_BLOBS_AVAILABLE: usize = 1234;
    const DUMMY_CONSTRAINTS_AVAILABLE: u32 = 12;

    fn test_slot_info(slot: u64) -> SlotInfo {
        SlotInfo {
            slot,
            gas_available: DUMMY_GAS_AVAILABLE,
            blobs_available: DUMMY_BLOBS_AVAILABLE,
            constraints_available: DUMMY_CONSTRAINTS_AVAILABLE,
        }
    }

    #[tokio::test]
    async fn test_reserve_blockspace_works_for_new_slot_within_limits() {
        let slot = 234;
        let slot_info = test_slot_info(slot);
        let slot_infos = Arc::new(RwLock::new(vec![slot_info]));
        let mut underwriter = Underwriter::new(slot_infos);

        let gas = 100;
        let blobs = 3;
        assert!(underwriter.reserve_blockspace(slot, gas, blobs).await.is_ok());
    }

    #[tokio::test]
    async fn test_reserve_blockspace_fails_if_target_slot_is_not_available() {
        let slot = 2;
        let slot_infos = Arc::new(RwLock::new(vec![test_slot_info(slot)]));
        let mut underwriter = Underwriter::new(slot_infos);

        let target_slot = 234;
        let gas = 100;
        let blobs = 3;
        let err = underwriter.reserve_blockspace(target_slot, gas, blobs).await.unwrap_err();
        assert_eq!(err, UnderwriterError::SlotNotAvailable { slot: target_slot });
    }

    #[tokio::test]
    async fn test_reserve_blockspace_fails_for_new_slot_that_exceeds_limits() {
        let target_slot = 234;
        let slot_infos = Arc::new(RwLock::new(vec![test_slot_info(target_slot)]));
        let mut underwriter = Underwriter::new(slot_infos);

        let gas = DUMMY_GAS_AVAILABLE + 1;
        let blobs = 3;
        let err = underwriter.reserve_blockspace(target_slot, gas, blobs).await.unwrap_err();
        assert_eq!(
            err,
            SlotInfoError::GasLimit { available: DUMMY_GAS_AVAILABLE, required: gas }.into()
        );
    }

    #[tokio::test]
    async fn test_reserve_blockspace_with_two_slots() {
        let target_slot_1 = 234;
        let target_slot_2 = 24;
        let slot_infos = Arc::new(RwLock::new(vec![
            test_slot_info(target_slot_1),
            test_slot_info(target_slot_2),
        ]));
        let mut underwriter = Underwriter::new(slot_infos);

        let gas = 100;
        let blobs = 3;
        assert!(underwriter.reserve_blockspace(target_slot_1, gas, blobs).await.is_ok());
        assert!(underwriter.reserve_blockspace(target_slot_1, gas, blobs).await.is_ok());
        assert!(underwriter.reserve_blockspace(target_slot_2, gas, blobs).await.is_ok());

        let expected_available = DUMMY_GAS_AVAILABLE - 2 * gas;
        let gas = expected_available + 1;
        let err = underwriter.reserve_blockspace(target_slot_1, gas, blobs).await.unwrap_err();
        assert_eq!(
            err,
            SlotInfoError::GasLimit { available: expected_available, required: gas }.into()
        );
    }

    #[tokio::test]
    async fn test_remove_old_slots() {
        let target_slot_1 = 234;
        let target_slot_2 = 24;
        let slot_infos = Arc::new(RwLock::new(vec![
            test_slot_info(target_slot_1),
            test_slot_info(target_slot_2),
        ]));
        let mut underwriter = Underwriter::new(slot_infos.clone());

        let gas = 100;
        let blobs = 3;
        assert!(underwriter.reserve_blockspace(target_slot_1, gas, blobs).await.is_ok());
        assert!(underwriter.reserve_blockspace(target_slot_1, gas, blobs).await.is_ok());
        assert!(underwriter.reserve_blockspace(target_slot_2, gas, blobs).await.is_ok());

        slot_infos.write().await.remove(1);
        let gas = 123406;
        let err = underwriter.reserve_blockspace(target_slot_1, gas, blobs).await.unwrap_err();
        assert_eq!(err, SlotInfoError::GasLimit { available: 123256, required: gas }.into());
        let err = underwriter.reserve_blockspace(target_slot_2, gas, blobs).await.unwrap_err();
        assert_eq!(err, UnderwriterError::SlotNotAvailable { slot: target_slot_2 })
    }

    fn get_test_signature() -> Signature {
        Signature::new(U256::ONE, U256::default(), false)
    }

    fn get_test_transaction() -> TxEnvelope {
        TxEnvelope::new_unhashed(TxEip1559::default().into(), get_test_signature())
    }

    #[tokio::test]
    async fn test_reserve_slot_with_calldata() {
        let target_slot = 10;
        let slot_infos = Arc::new(RwLock::new(vec![test_slot_info(target_slot)]));
        let mut underwriter = Underwriter::new(slot_infos.clone());

        let preconf_fee = PreconfFee { gas_fee: 10, blob_gas_fee: 150 };
        let request = SubmitTypeATransactionRequest {
            tip_transaction: get_test_transaction(),
            preconf_transaction: vec![],
            target_slot,
        };
        let signer = Address::random();
        let mut sender = MockSender::new();
        sender
            .expect_send()
            .withf(|request, _| match request {
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
