use eyre::Context;
use reth::providers::{BlockHashReader, ChainSpecProvider, ProviderFactory};
use reth_chainspec::ChainSpec;
use reth_db::{database::Database, open_db_read_only, DatabaseEnv};
use reth_provider::{providers::StaticFileProvider, StaticFileProviderFactory};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

// pub fn reth_db_provider() -> Arc<Mutex<ProviderFactory<Database>>> {
//     let db_path = Path::new("/Users/chirag-bgh/Library/Application Support/reth/holesky/db");
//     let db = Arc::new(open_db_read_only(db_path, Default::default()).unwrap());
//     let chain_spec = chain_spec();

//     let factory = ProviderFactory::new(
//         db.clone(),
//         chain_spec.clone(),
//         StaticFileProvider::read_only(db_path.join("static_files")).unwrap(),
//     );
// }

#[derive(Debug, Clone)]
pub struct ProviderFactoryReopener<DB> {
    provider_factory: Arc<Mutex<ProviderFactory<DB>>>,
    chain_spec: Arc<ChainSpec>,
    static_files_path: PathBuf,
}

impl<DB: Database + Clone> ProviderFactoryReopener<DB> {
    pub fn new(db: DB, chain_spec: Arc<ChainSpec>, static_files_path: PathBuf) -> Self {
        let provider_factory = ProviderFactory::new(
            db,
            chain_spec.clone(),
            StaticFileProvider::read_only(static_files_path.as_path()).unwrap(),
        );

        Self {
            provider_factory: Arc::new(Mutex::new(provider_factory)),
            chain_spec,
            static_files_path,
        }
    }
}

/// Open reth db and DB should be opened once per process but it can be cloned and moved to different threads.
pub fn create_provider_factory(
    reth_datadir: Option<&Path>,
    reth_db_path: Option<&Path>,
    reth_static_files_path: Option<&Path>,
    chain_spec: Arc<ChainSpec>,
) -> eyre::Result<ProviderFactoryReopener<Arc<DatabaseEnv>>> {
    let reth_db_path = match (reth_db_path, reth_datadir) {
        (Some(reth_db_path), _) => PathBuf::from(reth_db_path),
        (None, Some(reth_datadir)) => reth_datadir.join("db"),
        (None, None) => eyre::bail!("Either reth_db_path or reth_datadir must be provided"),
    };

    let db = open_reth_db(&reth_db_path)?;

    let reth_static_files_path = match (reth_static_files_path, reth_datadir) {
        (Some(reth_static_files_path), _) => PathBuf::from(reth_static_files_path),
        (None, Some(reth_datadir)) => reth_datadir.join("static_files"),
        (None, None) => {
            eyre::bail!("Either reth_static_files_path or reth_datadir must be provided")
        }
    };

    let provider_factory_reopener =
        ProviderFactoryReopener::new(db, chain_spec, reth_static_files_path);

    Ok(provider_factory_reopener)
}

fn open_reth_db(reth_db_path: &Path) -> eyre::Result<Arc<DatabaseEnv>> {
    Ok(Arc::new(
        reth_db::open_db_read_only(reth_db_path, Default::default()).context("DB open error")?,
    ))
}
