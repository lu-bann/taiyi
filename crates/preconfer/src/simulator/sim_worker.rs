use std::{sync::Arc, time::Duration};

use parking_lot::Mutex;
use reth_node_types::NodeTypesWithDB;
use reth_payload_builder::database::CachedReads;
use reth_provider::{providers::ProviderNodeTypes, ProviderFactory};
use tokio_util::sync::CancellationToken;

use super::{simulate::transact, state_cache::StateCacheDB, CurrentSimCtxs};

pub fn run_sim_worker<N: ProviderNodeTypes + Clone + Send + 'static>(
    worker_id: usize,
    sim_ctx: Arc<Mutex<CurrentSimCtxs>>,
    provider_factory: ProviderFactory<N>,
    cancellation: CancellationToken,
) {
    loop {
        if cancellation.is_cancelled() {
            return;
        }

        let current_sim_ctx = loop {
            let next_ctx = {
                let ctxs = sim_ctx.lock();
                ctxs.contexts.iter().next().map(|(_, v)| v.clone())
            };
            // @Perf chose random context so its more fair when we have 2 instead of 1
            if let Some(ctx) = next_ctx {
                break ctx;
            } else {
                // contexts are created for a duration of the slot so this is not a problem
                std::thread::sleep(Duration::from_millis(50));
            }
        };

        let mut cached_reads = CachedReads::default();
        while let Ok(task) = current_sim_ctx.requests.recv() {
            let state_provider = provider_factory
                .history_by_block_hash(current_sim_ctx.block_ctx.attributes.parent)
                .unwrap();
            let mut state_cache_db =
                StateCacheDB::new(Arc::new(state_provider)).with_cached_reads(cached_reads.clone());
            let sim_outcome = transact(task.tx, &mut state_cache_db);
            
        }
    }
}
