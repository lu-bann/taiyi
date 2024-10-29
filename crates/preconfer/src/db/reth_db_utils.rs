use std::{path::Path, sync::Arc};

use eyre::Result;
use reth_chainspec::ChainSpec;
use reth_db::DatabaseEnv;
use reth_node_ethereum::EthereumNode;
use reth_node_types::NodeTypesWithDBAdapter;
use reth_provider::{providers::StaticFileProvider, ProviderFactory};

fn open_reth_db(reth_db_path: &Path) -> Result<Arc<DatabaseEnv>> {
    Ok(Arc::new(reth_db::open_db_read_only(reth_db_path, Default::default())?))
}

pub fn create_provider_factory(
    reth_datadir: &Path,
    chain_spec: Arc<ChainSpec>,
) -> ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>> {
    let reth_db_path = reth_datadir.join("db");
    let reth_static_files_path = reth_datadir.join("static_files");
    let db = open_reth_db(&reth_db_path).expect("Failed to open reth db");

    ProviderFactory::<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>::new(
        db,
        chain_spec.clone(),
        StaticFileProvider::read_only(reth_static_files_path.as_path(), false).expect(""),
    )
}
