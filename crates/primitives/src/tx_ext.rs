use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Encodable2718;
use ethereum_consensus::{deneb::mainnet::MAX_BYTES_PER_TRANSACTION, ssz::prelude::ByteList};

pub trait TxExt {
    fn to_ssz_bytes(&self) -> ByteList<MAX_BYTES_PER_TRANSACTION>;
}

impl TxExt for TxEnvelope {
    fn to_ssz_bytes(&self) -> ByteList<MAX_BYTES_PER_TRANSACTION> {
        let mut tx_bytes = Vec::new();
        self.encode_2718(&mut tx_bytes);
        let tx_ref: &[u8] = tx_bytes.as_ref();
        tx_ref.try_into().expect("tx bytes too big")
    }
}
