use sp1_build::BuildArgs;

fn main() {
    let args = BuildArgs { ignore_rust_version: true, ..Default::default() };

    sp1_build::build_program_with_args("../../crates/poi", args.clone());
}
