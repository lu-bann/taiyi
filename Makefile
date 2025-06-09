build:
	cargo build --release

test:
	cargo test

coverage:
	cargo llvm-cov

coverage-report:
	cargo llvm-cov --html

format:
	cargo +nightly fmt --all
	cargo sort --workspace --grouped

e2e-network:
	bash scripts/devnet/start-devnet.sh

e2e-setup:
	bash scripts/devnet/initialize.sh
	bash scripts/devnet/delegate.sh
	bash scripts/devnet/register-underwriter-avs.sh
	bash scripts/devnet/register-validator-avs.sh

e2e-test:
	bash scripts/devnet/start-e2e-tests.sh $(ARGS)

e2e-fraud-test:
	bash scripts/devnet/start-e2e-fraud-tests.sh $(ARGS)

e2e-clean:
	bash scripts/devnet/clean.sh

make e2e:
	make e2e-network
	make e2e-setup
	make e2e-test

lint:
	cargo +nightly fmt --all -- --check
	cargo +nightly clippy --all -- -D warnings -A clippy::derive_partial_eq_without_eq -D clippy::unwrap_used -A clippy::uninlined-format-args
	cargo sort --check --workspace --grouped
	cargo machete
