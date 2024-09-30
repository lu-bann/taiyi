use commit_boost::prelude::*;
use eyre::Result;

mod types;
use types::ExtraConfig;

#[tokio::main]
async fn main() -> Result<()> {
    let (_pbs_config, _extra) = load_pbs_custom_config::<ExtraConfig>()?;
    Ok(())
}
