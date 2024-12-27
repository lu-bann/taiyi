set -x

# set default enclave name
if [ -z "$ENCLAVE_NAME" ]; then
  export ENCLAVE_NAME="luban"
fi

if [ -z "$WORKING_DIR" ]; then
  export WORKING_DIR="$(pwd)"
fi

if kurtosis enclave inspect $ENCLAVE_NAME >/dev/null 2>&1; then
  export EXECUTION_URL="http://$(kurtosis port print luban el-1-reth-lighthouse rpc)"
  export BEACON_URL="$(kurtosis port print luban cl-1-lighthouse-reth http)"
  export RELAY_URL="http://$(kurtosis port print luban helix-relay api)"
fi

