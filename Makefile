build:
	cargo build --release

test:
	cargo test

format:
	cargo +nightly fmt --all
	cargo sort --workspace --grouped

e2e-network:
	bash scripts/devnet/start-devnet.sh

e2e-setup:
	bash scripts/devnet/initialize.sh
	bash scripts/devnet/delegate.sh

e2e-test:
	bash scripts/devnet/start-e2e-tests.sh $(ARGS)

e2e-clean:
	bash scripts/devnet/clean.sh

make e2e:
	make e2e-network
	make e2e-setup
	make e2e-test

lint:
	cargo +nightly fmt --all -- --check
	cargo clippy --all -- -D warnings -A clippy::derive_partial_eq_without_eq -D clippy::unwrap_used -D clippy::uninlined_format_args
	cargo sort --check --workspace --grouped
	cargo machete
