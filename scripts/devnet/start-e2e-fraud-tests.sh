set -xe

source "$(dirname "$0")/config.sh"

cargo test --package taiyi-e2e-tests --features fraud-test "$@" -- --show-output --test-threads=1