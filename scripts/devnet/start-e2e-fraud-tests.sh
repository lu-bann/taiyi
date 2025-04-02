set -xe

source "$(dirname "$0")/config.sh"

cargo build
cargo test --package taiyi-e2e-tests --features fraud-test "$@" -- --show-output --test-threads=1