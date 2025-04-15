set -xe

source "$(dirname "$0")/config.sh"

if kurtosis enclave inspect $ENCLAVE_NAME >/dev/null 2>&1; then
  export EXECUTION_CLIENT_URL="http://$(kurtosis port print luban el-1-geth-lighthouse rpc)"
  export BEACON_CLIENT_URL="$(kurtosis port print luban cl-1-lighthouse-geth http)"
fi

export UNDERWRITER_URL="http://127.0.0.1:5656"
export PRIVATE_KEY="bf3beef3bd999ba9f2451e06936f0423cd62b815c9233dd3bc90f7e02a1e8673"
export UNDERWRITER_ADDRESS=0xD8F3183DEF51A987222D845be228e0Bbb932C222

cargo run -p type_a