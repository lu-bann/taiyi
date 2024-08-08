use reth::primitives::Genesis;
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder, HOLESKY};
use std::{fs::File, io::BufReader};

pub fn chainspec_builder(chain_id: u64) -> ChainSpec {
    match chain_id {
        // mainnet
        1 => ChainSpecBuilder::mainnet().build(),
        // Holesky
        17000 => ChainSpec {
            chain: HOLESKY.chain,
            genesis: HOLESKY.genesis.clone(),
            hardforks: HOLESKY.hardforks.clone(),
            genesis_hash: Some(HOLESKY.genesis_hash()),
            paris_block_and_final_difficulty: HOLESKY.paris_block_and_final_difficulty,
            deposit_contract: HOLESKY.deposit_contract.clone(),
            base_fee_params: HOLESKY.base_fee_params.clone(),
            prune_delete_limit: HOLESKY.prune_delete_limit,
            max_gas_limit: HOLESKY.max_gas_limit,
        },
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
            chain_spec_builder.build()
        }
        _ => panic!("Unknown chain id"),
    }
}
