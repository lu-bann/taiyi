set -xe

source "$(dirname "$0")/config.sh"

export PRIVATE_KEY="bf3beef3bd999ba9f2451e06936f0423cd62b815c9233dd3bc90f7e02a1e8673"
export TAIYI_PRECONFER_URL="http://127.0.0.1:5656"
cargo run --example submit-preconf-request
