use reth_revm::{
    primitives::{hex, BlockEnv, CfgEnv, EVMError, Env, ResultAndState, SpecId, TransactTo, TxEnv},
    Evm,
};
use taiyi_primitives::PreconfTx;

use super::state_cache::StateCacheDB;
use crate::error::SimulationError;

pub enum SimulationOutcome {
    Success(ResultAndState),
    Failure,
}
struct PreconfTxWrapper;

impl PreconfTxWrapper {
    fn new() -> Self {
        Self
    }

    fn fill_tx_env(&self, tx_env: &mut TxEnv, preconf_tx: PreconfTx) {
        tx_env.caller = preconf_tx.from;
        tx_env.transact_to = TransactTo::Call(preconf_tx.to);
        tx_env.data = hex::decode(preconf_tx.call_data.clone()).unwrap().into();
    }
}

pub fn transact(
    preconf_tx: PreconfTx,
    state: &mut StateCacheDB,
) -> eyre::Result<SimulationOutcome, SimulationError> {
    let mut db = state.new_db_ref();

    let mut tx_env = TxEnv::default();
    PreconfTxWrapper::new().fill_tx_env(&mut tx_env, preconf_tx);

    let cfg = CfgEnv::default().with_chain_id(reth_chainspec::ChainSpec::default().chain().id());
    let env = Env { cfg, block: BlockEnv::default(), tx: tx_env };
    let mut evm = Evm::builder()
        .with_spec_id(SpecId::default())
        .with_env(Box::new(env))
        .with_db(db.as_mut())
        .build();

    match evm.transact() {
        Ok(res) => Ok(SimulationOutcome::Success(res)),
        Err(EVMError::Transaction(_)) => Ok(SimulationOutcome::Failure),
        Err(e) => Err(SimulationError::SimulationError(e.to_string())),
    }
    // evm.context.evm.inner.db.commit(result_and_state.state);
}
