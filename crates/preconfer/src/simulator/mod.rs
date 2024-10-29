#![allow(dead_code)]

mod reth_db_utils;
mod sim_worker;
mod simulate;
mod state_cache;

use std::{collections::HashMap, sync::Arc};

use parking_lot::Mutex;
use reth_chainspec::ChainSpec;
pub use reth_db_utils::create_provider_factory;
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_provider::{providers::ProviderNodeTypes, ProviderFactory};
use reth_revm::primitives::{BlockEnv, CfgEnvWithHandlerCfg};
use simulate::SimulationOutcome;
use taiyi_primitives::PreconfTx;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct SimulationPool<N: ProviderNodeTypes> {
    provider_factory: ProviderFactory<N>,
    running_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    current_ctxs: Arc<Mutex<CurrentSimCtxs>>,
    worker_threads: Vec<std::thread::JoinHandle<()>>,
}

impl<N: ProviderNodeTypes + Clone + Send + 'static> SimulationPool<N> {
    pub fn new(
        provider_factory: ProviderFactory<N>,
        num_workers: usize,
        global_cancellation: CancellationToken,
    ) -> Self {
        let mut result = Self {
            provider_factory,
            running_tasks: Arc::new(Mutex::new(Vec::new())),
            current_ctxs: Arc::new(Mutex::new(CurrentSimCtxs { contexts: HashMap::default() })),
            worker_threads: Vec::new(),
        };
        for i in 0..num_workers {
            let ctx = Arc::clone(&result.current_ctxs);
            let provider = result.provider_factory.clone();
            let cancel = global_cancellation.clone();
            let handle = std::thread::Builder::new()
                .name(format!("sim_thread:{i}"))
                .spawn(move || {
                    sim_worker::run_sim_worker(i, ctx, provider, cancel);
                })
                .expect("Failed to start sim worker thread");
            result.worker_threads.push(handle);
        }
        result
    }
}

/// All active SimulationContexts
#[derive(Debug)]
pub struct CurrentSimCtxs {
    pub contexts: HashMap<u64, SimulationContext>,
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
