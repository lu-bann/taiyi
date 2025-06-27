use std::{
    path::Path,
    process::{Child, Command},
    sync::{Arc, Mutex},
    thread,
};

use clap::Parser;
use taiyi_cmd::UnderwriterCommand;
use tracing::{error, info};

use crate::{
    constant::{UNDERWRITER_BLS_SK, UNDERWRITER_ECDSA_SK},
    utils::TestConfig,
};

// The struct that holds the process.
// Its Drop implementation will handle cleanup.
#[derive(Debug)]
pub struct TaiyiProcess {
    // We wrap the Child in a Mutex<Option<...>> to allow us
    // to "take" it during drop, which is a common pattern for Drop logic.
    process: Mutex<Option<Child>>,
}

impl TaiyiProcess {
    pub fn new(config: &TestConfig) -> Result<Self, std::io::Error> {
        let network_dir = format!("{}/{}", config.working_dir, "el_cl_genesis_data");
        let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("path");
        let manifest_path = Path::new(manifest.as_str());
        let binary = manifest_path.parent().expect("parent").join("target/debug/taiyi");
        let process = Command::new(binary)
            .args([
                "underwriter",
                "--bls-sk",
                UNDERWRITER_BLS_SK,
                "--ecdsa-sk",
                UNDERWRITER_ECDSA_SK,
                "--network",
                &network_dir,
                "--execution-rpc-url",
                &config.execution_url,
                "--beacon-rpc-url",
                &config.beacon_url,
                "--relay-url",
                &config.relay_url,
                "--taiyi-rpc-port",
                &config.taiyi_port.to_string(),
                "--taiyi-escrow-address",
                &config.taiyi_core.to_string(),
            ])
            .spawn()?;

        Ok(TaiyiProcess { process: Mutex::new(Some(process)) })
    }
}

// when the last Arc<TaiyiProcess> is dropped,
// this code will automatically run.
impl Drop for TaiyiProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.process.lock().unwrap().take() {
            info!("last TaiyiProcess handle dropped. killing taiyi process.");
            if let Err(e) = child.kill() {
                error!("failed to kill taiyi process: {}", e);
            }
            if let Err(e) = child.wait() {
                error!("failed to wait for taiyi process exit: {}", e);
            }
        }
    }
}
