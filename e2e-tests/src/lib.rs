#![allow(unused_imports, dead_code)]
#![cfg(test)]

use alloy_provider::{
    fillers::{
        BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
    },
    network::{Ethereum, EthereumWallet},
    Identity, RootProvider,
};
use alloy_transport::BoxTransport;

mod constant;
mod contract_call;
#[cfg(feature = "fraud-test")]
mod test_fraud_proof;

#[cfg(not(feature = "fraud-test"))]
mod test_preconf_workflow;

mod utils;

type TestProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<BoxTransport>,
    BoxTransport,
    Ethereum,
>;
