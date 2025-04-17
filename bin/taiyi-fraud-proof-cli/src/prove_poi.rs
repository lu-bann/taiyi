use std::{fs::File, path::PathBuf};

use eyre::format_err;
use serde::Deserialize;
use sp1_sdk::{include_elf, network::FulfillmentStrategy, Prover, ProverClient, SP1Stdin};
use tracing::info;

#[derive(clap::ValueEnum, Debug, Clone, PartialEq, Eq)]
pub enum SP1Prover {
    Cpu,
    Network,
}

#[derive(clap::Args, Debug, Clone)]
pub struct ProveArgs {
    #[arg(long, short, help = "Verbosity level (0-4)", action = clap::ArgAction::Count)]
    pub v: u8,

    /// Path to the input data
    #[clap(long)]
    pub input_data_path: String,

    /// Type of SP1 prover
    #[clap(long, default_value = "cpu")]
    pub sp1_prover: SP1Prover,
}

#[derive(Clone, Debug, Deserialize, Default, PartialEq)]
pub struct InputData {
    pub n: u32,
}

const ELF: &[u8] = include_elf!("taiyi-poi");

pub async fn prove(args: ProveArgs) -> eyre::Result<()> {
    // 1. Read input data
    info!("Reading input data from {}", args.input_data_path);
    let path = PathBuf::from(&args.input_data_path);
    let reader = File::open(&path)?;
    let input_data: InputData = serde_json::from_reader(reader)?;
    info!("Input data: {:?}", input_data);

    // 2. Prepare SP1 program input
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_data.n);

    // 3. Select prover, execute program and generate proof
    if args.sp1_prover == SP1Prover::Cpu {
        // Program execution
        info!("Using the local CPU prover");
        let client = ProverClient::builder().cpu().build();

        info!("Executing program");
        let (mut public_values, report) =
            client.execute(ELF, &stdin).run().map_err(|err| format_err!(err))?;
        info!("Executed program with {} cycles", report.total_instruction_count());

        // Log public values
        let n = public_values.read::<u32>();
        let a = public_values.read::<u32>();
        let b = public_values.read::<u32>();
        info!("Public values: n: {}, a: {}, b: {}", n, a, b);

        // Proof generation
        info!("Generating proof of execution");

        let (pk, vk) = client.setup(ELF);
        info!("Generated setup keys");

        let proof = client.prove(&pk, &stdin).core().run().map_err(|err| format_err!(err))?;
        info!("Generated proof");

        client.verify(&proof, &vk).expect("verification failed");

        info!("verified proof");
    } else {
        info!("Using the network SP1 prover.");
        let client = ProverClient::builder().network().build();

        info!("Executing program");
        let (mut public_values, report) =
            client.execute(ELF, &stdin).run().map_err(|err| format_err!(err))?;
        info!("Executed program with {} cycles", report.total_instruction_count());

        // Log public values
        let n = public_values.read::<u32>();
        let a = public_values.read::<u32>();
        let b = public_values.read::<u32>();
        info!("Public values: n: {}, a: {}, b: {}", n, a, b);

        // Proof generation
        info!("Generating proof of execution");

        let (pk, vk) = client.setup(ELF);
        info!("Generated setup keys");

        let proof = client
            .prove(&pk, &stdin)
            .strategy(FulfillmentStrategy::Hosted)
            .skip_simulation(true)
            .plonk()
            .run()
            .map_err(|err| format_err!(err))?;
        info!("Generated proof");

        client.verify(&proof, &vk).expect("verification failed");

        info!("verified proof");
    }

    Ok(())
}
