use reth_revm::{
    primitives::{hex, BlockEnv, CfgEnv, Env, SpecId, TransactTo, TxEnv},
    Database, DatabaseCommit, Evm, State,
};
use taiyi_primitives::{PreconfRequest, PreconfTx};

use super::state_cache::StateCacheDB;

pub enum SimulationOutcome {
    Success,
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

pub fn transact(preconf_tx: PreconfTx, state: &mut StateCacheDB) {
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

    let result_and_state = evm.transact().unwrap();
    evm.context.evm.inner.db.commit(result_and_state.state);
}
