set -xe

source "$(dirname "$0")/config.sh"

cargo build
if [ $# -eq 0 ]; then
    cargo test --package taiyi-e2e-tests --lib test_preconf_workflow -- --show-output
else
    cargo test --package taiyi-e2e-tests --lib -- test_preconf_workflow::$1 --exact --show-output
fi
