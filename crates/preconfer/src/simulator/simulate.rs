use alloy_primitives::Bytes;
use taiyi_primitives::PreconfRequest;
use trevm::{
    revm::{
        primitives::{hex, Address, TransactTo, TxEnv},
        EvmBuilder, InMemoryDB,
    },
    trevm_aliases, NoopBlock, NoopCfg, TrevmBuilder, Tx,
};
struct PreconfTxWrapper {
    from: Address,
    to: Address,
    call_data: Bytes,
}

impl PreconfTxWrapper {
    fn new(req: PreconfRequest) -> Self {
        let preconf_tx = req.preconf_tx.unwrap();
        Self { from: preconf_tx.from, to: preconf_tx.to, call_data: preconf_tx.call_data }
    }
}

impl Tx for PreconfTxWrapper {
    fn fill_tx_env(&self, tx_env: &mut TxEnv) {
        tx_env.caller = self.from;
        tx_env.transact_to = TransactTo::Call(self.to);
        tx_env.data = hex::decode(self.call_data.clone()).unwrap().into();
    }
}

// Produce aliases for the Trevm type
trevm_aliases!(InMemoryDB);

fn simulate(preconf_req: PreconfRequest) {
    let db = InMemoryDB::default();

    let evm =
        EvmBuilder::default().with_db(db).build_trevm().fill_cfg(&NoopCfg).fill_block(&NoopBlock);

    let preconf_tx = PreconfTxWrapper::new(preconf_req);
    let evm = evm.fill_tx(&preconf_tx).run();

    match evm {
        Ok(res) => {
            let res = res.result_and_state();
            println!("Execution result: {res:#?}");
        }
        Err(e) => {
            println!("Execution error: {e:?}");
        }
    };
}
