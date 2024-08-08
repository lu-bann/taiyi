use reth::primitives::Genesis;
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder, HOLESKY, MAINNET};
use std::{fs::File, io::BufReader, sync::Arc};

pub fn chainspec_builder(chain_id: u64) -> Arc<ChainSpec> {
    match chain_id {
        // mainnet
        1 => MAINNET.clone(),
        // Holesky
        17000 => HOLESKY.clone(),
        // Helder
        7014190335 => {
            // Parse helder genesis specs
            let genesis: Genesis = serde_json::from_reader(BufReader::new(
                File::open("helder.json").expect("Failed to open genesis file"),
            ))
            .expect("Failed to parse genesis file");

            let chain_spec_builder = ChainSpecBuilder::default()
                .chain(Chain::from(chain_id))
                .genesis(genesis)
                .cancun_activated();
            chain_spec_builder.build().into()
        }
        _ => panic!("Unknown chain id"),
    }
}
