mod allocation_manager;
mod avsdirectory;
mod eigenlayer;
mod erc20;
mod registry;
mod taiyi_core;
mod taiyi_middleware;

pub use allocation_manager::*;
pub use avsdirectory::*;
pub use eigenlayer::*;
pub use erc20::*;
pub use registry::*;
pub use taiyi_core::TaiyiCore;
pub use taiyi_middleware::*;

use alloy_provider::{
    fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    Identity, RootProvider,
};

pub type Provider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;
pub type TaiyiCoreInstance = TaiyiCore::TaiyiCoreInstance<Provider>;
