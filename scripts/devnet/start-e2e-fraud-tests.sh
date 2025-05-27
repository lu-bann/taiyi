set -xe

source "$(dirname "$0")/config.sh"

cargo build
if [ $# -gt 0 ]; then
    cargo test --release --package taiyi-e2e-tests --lib test_fraud_proof -- "$@" --exact --show-output
else
    cargo test --release --package taiyi-e2e-tests --lib test_fraud_proof -- --show-output
fi