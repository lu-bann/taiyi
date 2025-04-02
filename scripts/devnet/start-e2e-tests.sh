set -xe

source "$(dirname "$0")/config.sh"

cargo build
cargo test --package taiyi-e2e-tests --lib test_preconf_workflow "$@" -- --show-output