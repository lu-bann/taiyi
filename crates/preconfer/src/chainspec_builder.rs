use ethereum_consensus::networks::Network;
use reth::primitives::Genesis;
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder, HOLESKY, MAINNET};
use std::{fs::File, io::BufReader, sync::Arc};

pub fn chainspec_builder(network: Network) -> Arc<ChainSpec> {
    match network {
        Network::Mainnet => MAINNET.clone(),
        Network::Holesky => HOLESKY.clone(),
        Network::Custom(config_path) => {
            // Parse helder genesis specs
            let genesis: Genesis = serde_json::from_reader(BufReader::new(
                File::open(config_path).expect("Failed to open genesis file"),
            ))
            .expect("Failed to parse genesis file");

            let chain_spec_builder = ChainSpecBuilder::default()
                .chain(Chain::from(genesis.config.chain_id))
                .genesis(genesis)
                .cancun_activated();
            chain_spec_builder.build().into()
        }
        _ => panic!("Unsupported network"),
    }
}
