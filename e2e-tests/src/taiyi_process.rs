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
    process: Child,
}

impl TaiyiProcess {
    pub fn new(config: &TestConfig) -> Result<Self, std::io::Error> {
        let manifest =
            std::env::var("CARGO_MANIFEST_DIR").expect("no CARGO_MANIFEST_DIR in environment");
        let manifest_path = Path::new(manifest.as_str());
        let binary = manifest_path.parent().expect("parent").join("target/debug/taiyi");
        let mut command = Command::new(binary);
        command.args([
            "underwriter",
            "--bls-sk",
            UNDERWRITER_BLS_SK,
            "--ecdsa-sk",
            UNDERWRITER_ECDSA_SK,
            "--fork-version",
            &format!("0x{}", hex::encode(config.fork_version)),
            "--genesis-timestamp",
            &config.genesis_time.to_string(),
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
        ]);
        info!("Starting taiyi process with command: {:?}", command);
        let process = command.spawn()?;

        Ok(TaiyiProcess { process })
    }
    pub fn kill(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait(); // Wait for the process to exit
    }
}

pub struct ResourceManager {
    resource: Arc<Mutex<TaiyiProcess>>,
    ref_count: Arc<Mutex<usize>>,
}

impl ResourceManager {
    pub fn new(test_config: &TestConfig) -> Self {
        let taiyi = TaiyiProcess::new(test_config).expect("taiyi process failed");
        ResourceManager {
            resource: Arc::new(Mutex::new(taiyi)),
            ref_count: Arc::new(Mutex::new(0)),
        }
    }

    pub fn acquire(&self) -> ResourceHandle {
        let mut count = self.ref_count.lock().unwrap();
        *count += 1;
        ResourceHandle { resource: self.resource.clone(), ref_count: self.ref_count.clone() }
    }
}

#[derive(Debug)]
pub struct ResourceHandle {
    resource: Arc<Mutex<TaiyiProcess>>,
    ref_count: Arc<Mutex<usize>>,
}

impl Drop for ResourceHandle {
    fn drop(&mut self) {
        let mut count = self.ref_count.lock().unwrap();
        *count -= 1;

        if *count == 0 {
            // Last handle is being dropped, perform cleanup
            if let Ok(mut resource) = self.resource.lock() {
                resource.kill();
            }
        }
    }
}
