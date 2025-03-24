use sp1_build::BuildArgs;

fn main() {
    let args = BuildArgs { ignore_rust_version: true, ..Default::default() };

    sp1_build::build_program_with_args("../crates/sp1-poi", args.clone());
    sp1_build::build_program_with_args("../crates/sp1-poni", args.clone());
    sp1_build::build_program_with_args("../crates/sp1-verifier", args.clone());
}
