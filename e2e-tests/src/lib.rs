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
// mod test_fraud_proof;

mod test_preconf_workflow;

mod taiyi_process;
mod utils;

type TestProvider = FillProvider<
    JoinFill<
        JoinFill<
            alloy_provider::Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;
