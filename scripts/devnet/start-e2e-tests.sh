set -xe

source "$(dirname "$0")/config.sh"

RUST_LOG=info cargo test --package taiyi-e2e-tests -- test_commitment_apis $1