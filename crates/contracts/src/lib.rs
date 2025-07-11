mod allocation_manager;
mod avsdirectory;
mod eigenlayer;
mod erc20;
mod registry;
mod taiyi_escrow;
mod taiyi_middleware;

pub use allocation_manager::*;
pub use avsdirectory::*;
pub use eigenlayer::*;
pub use erc20::*;
pub use registry::*;
pub use taiyi_escrow::TaiyiEscrow;
pub use taiyi_middleware::*;

use alloy::providers::{
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
pub type TaiyiEscrowInstance = TaiyiEscrow::TaiyiEscrowInstance<Provider>;
