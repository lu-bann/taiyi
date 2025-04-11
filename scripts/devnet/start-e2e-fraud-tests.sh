set -xe

source "$(dirname "$0")/config.sh"

cargo build
cargo test --release --package taiyi-e2e-tests --lib test_fraud_proof "$@" -- --show-output