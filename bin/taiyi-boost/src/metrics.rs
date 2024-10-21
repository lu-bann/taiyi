use commit_boost::prelude::*;
use eyre::Result;

pub fn init_metrics() -> Result<()> {
    PbsService::init_metrics()
}
