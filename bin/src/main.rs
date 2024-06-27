fn main() {
    if let Err(err) = luban_cli::run() {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
