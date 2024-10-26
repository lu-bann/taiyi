mod reth_db_utils;
mod simulate;
mod state_cache;

use std::{collections::HashMap, sync::Arc};

use parking_lot::Mutex;
use reth_chainspec::ChainSpec;
pub use reth_db_utils::create_provider_factory;
use reth_node_types::NodeTypesWithDB;
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_provider::ProviderFactory;
use reth_revm::primitives::{BlockEnv, CfgEnvWithHandlerCfg};
use simulate::SimulationOutcome;
use taiyi_primitives::PreconfTx;
use tokio::{sync::mpsc, task::JoinHandle};

#[derive(Debug)]
pub struct SimulationPool<N: NodeTypesWithDB> {
    provider_factory: ProviderFactory<N>,
    running_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    current_ctxs: Arc<Mutex<CurrentSimCtxs>>,
    worker_threads: Vec<std::thread::JoinHandle<()>>,
}

/// All active SimulationContexts
#[derive(Debug)]
pub struct CurrentSimCtxs {
    pub contexts: HashMap<u64, CurrentSimCtxs>,
}
/// Struct representing the need of order simulation for a particular block.
#[derive(Debug, Clone)]
pub struct SimulationContext {
    pub block_ctx: BlockContext,
    /// Simulation requests come in through this channel.
    pub requests: flume::Receiver<SimulationRequest>,
    /// Simulation results go out through this channel.
    pub results: mpsc::Sender<SimulationOutcome>,
}

pub struct SimulationRequest {
    pub target_block: u64,
    pub tx: PreconfTx,
}

#[derive(Debug, Clone)]
pub struct BlockContext {
    pub block_env: BlockEnv,
    pub initialized_cfg: CfgEnvWithHandlerCfg,
    pub attributes: EthPayloadBuilderAttributes,
    pub chain_spec: Arc<ChainSpec>,
}
