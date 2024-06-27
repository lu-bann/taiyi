build:
	cargo build --release

test:
	cargo test --workspace

format:
	cargo +nightly fmt --all
	cargo sort --workspace --grouped

lint:
	cargo +nightly fmt --all -- --check
	cargo clippy --all -- -D warnings -A clippy::derive_partial_eq_without_eq -D clippy::unwrap_used -D clippy::uninlined_format_args
	cargo sort --check --workspace --grouped
	cargo +nightly udeps --workspace
