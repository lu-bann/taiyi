use reth_revm::{
    primitives::{hex, BlockEnv, CfgEnv, Env, SpecId, TransactTo, TxEnv},
    Evm,
};
use taiyi_primitives::PreconfRequest;

use super::state_cache::StateCacheDB;
struct PreconfTxWrapper;

impl PreconfTxWrapper {
    fn new() -> Self {
        Self
    }

    fn fill_tx_env(&self, tx_env: &mut TxEnv, preconf_req: PreconfRequest) {
        let preconf_tx = preconf_req.preconf_tx.unwrap();
        tx_env.caller = preconf_tx.from;
        tx_env.transact_to = TransactTo::Call(preconf_tx.to);
        tx_env.data = hex::decode(preconf_tx.call_data.clone()).unwrap().into();
    }
}

pub fn transact(preconf_req: PreconfRequest, state: &mut StateCacheDB) {
    let mut db = state.new_db_ref();

    let mut tx_env = TxEnv::default();
    PreconfTxWrapper::new().fill_tx_env(&mut tx_env, preconf_req);

    let cfg = CfgEnv::default().with_chain_id(reth_chainspec::ChainSpec::default().chain().id());
    let env = Env { cfg, block: BlockEnv::default(), tx: tx_env };
    let mut evm = Evm::builder()
        .with_spec_id(SpecId::default())
        .with_env(Box::new(env))
        .with_db(db.as_mut())
        .build();

    evm.transact();
}
