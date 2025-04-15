set -xe

source "$(dirname "$0")/config.sh"

if kurtosis enclave inspect $ENCLAVE_NAME >/dev/null 2>&1; then
  export EXECUTION_URL="http://`kurtosis port print luban el-1-geth-lighthouse rpc`"
  export BEACON_URL="`kurtosis port print luban cl-1-lighthouse-geth http`"
  export HELIX_URL="http://`kurtosis port print luban helix-relay api`"
fi

cargo run --bin taiyi underwriter \
  --bls-sk 4942d3308d3fbfbdb977c0bf4c09cb6990aec9fd5ce24709eaf23d96dba71148 \
  --ecdsa-sk 0xc5114526e042343c6d1899cad05e1c00ba588314de9b96929914ee0df18d46b2 \
  --network $WORKING_DIR/el_cl_genesis_data \
  --execution-rpc-url $EXECUTION_URL \
  --beacon-rpc-url $BEACON_URL \
  --relay-url $HELIX_URL \
  --taiyi-escrow-address $TAIYI_CORE_ADDRESS
