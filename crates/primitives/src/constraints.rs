use alloy_rpc_types_beacon::BlsPublicKey;
use ethereum_consensus::{
    bellatrix::mainnet::Transaction,
    crypto::{PublicKey, Signature},
    deneb::{compute_domain, verify_signed_data, Domain, DomainType},
    ssz::prelude::*,
    state_transition::Context,
};
use ssz_rs::{prelude::SimpleSerialize, List};

use crate::PreconfRequest;
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;
#[derive(
    Debug, Clone, serde::Serialize, serde::Deserialize, SimpleSerialize, Default, PartialEq,
)]
pub struct Constraint {
    tx: Transaction,
}

#[derive(
    Debug, Default, Clone, serde::Serialize, serde::Deserialize, SimpleSerialize, PartialEq,
)]
pub struct ConstraintsMessage {
    slot: u64,
    constraints: List<List<Constraint, MAX_TRANSACTIONS_PER_BLOCK>, MAX_TRANSACTIONS_PER_BLOCK>,
}

#[derive(Debug, Clone, serde::Serialize, SimpleSerialize, serde::Deserialize)]
pub struct SignedConstraintsMessage {
    pub message: ConstraintsMessage,
    /// Signature over `message`. Must be signed by the key relating to: `message.public_key`.
    pub signature: Signature,
}

pub fn compute_builder_domain(context: &Context) -> Result<Domain, String> {
    let domain_type = DomainType::ApplicationBuilder;
    compute_domain(domain_type, None, None, context).map_err(|e| e.to_string())
}

impl SignedConstraintsMessage {
    pub fn new(message: ConstraintsMessage, signature: Signature) -> Self {
        Self { message, signature }
    }

    pub fn verify(&self, public_key: &BlsPublicKey, context: &Context) -> Result<bool, String> {
        let domain = compute_builder_domain(context)?;
        let pubkey = PublicKey::try_from(public_key.as_ref()).map_err(|e| e.to_string())?;
        verify_signed_data(&self.message, &self.signature, &pubkey, domain)
            .map_err(|e| e.to_string())?;
        Ok(true)
    }
}

impl TryFrom<Vec<PreconfRequest>> for ConstraintsMessage {
    type Error = String;

    fn try_from(value: Vec<PreconfRequest>) -> Result<Self, Self::Error> {
        let first = value.first().ok_or("No preconf requests".to_string())?;
        let slot = first.preconf_conditions.slot;
        let constraints: Vec<List<Constraint, MAX_TRANSACTIONS_PER_BLOCK>> = value
            .into_iter()
            .map(|preconf_request| {
                if preconf_request.preconf_conditions.slot != slot {
                    Err("Slot mismatch".to_string())
                } else {
                    preconf_request
                        .preconf_tx
                        .ok_or("No preconf tx".to_string())
                        .map(|tx| {
                            let re: &[u8] = tx.as_ref();
                            vec![Constraint {
                                tx: re.try_into().expect("tx"),
                            }]
                            .try_into()
                            .expect("constraint")
                        })
                }
            })
            .collect::<Result<Vec<List<Constraint, MAX_TRANSACTIONS_PER_BLOCK>>, String>>()?;
        Ok(Self {
            slot,
            constraints: constraints.try_into().expect("constraints"),
        })
    }
}

// generate test cases for ConstraintsMessage
#[cfg(test)]
mod constraints_message_tests {
    use super::*;
    use crate::PreconfRequest;

    #[test]
    fn test_try_from_vec_preconf_request() {
        let preconf_request = PreconfRequest {
            tip_tx: Default::default(),
            preconf_conditions: Default::default(),
            init_signature: Default::default(),
            tip_tx_signature: Default::default(),
            preconfer_signature: Default::default(),
            preconf_tx: Some(vec![1, 2, 3]),
        };
        let tx_data = vec![1, 2, 3];
        let tx_data_ref: &[u8] = tx_data.as_ref();
        let tx: Transaction = tx_data_ref.try_into().expect("tx");
        let constraints_message = ConstraintsMessage {
            slot: 0,
            constraints: vec![vec![Constraint { tx }].try_into().expect("constraint")]
                .try_into()
                .expect("constraints"),
        };
        assert_eq!(
            ConstraintsMessage::try_from(vec![preconf_request.clone()]),
            Ok(constraints_message.clone())
        );
    }
}
