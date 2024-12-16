set -xe

source "$(dirname "$0")/config.sh"

export EXECUTION_URL="http://`kurtosis port print luban el-1-reth-lighthouse rpc`"
export BEACON_URL="`kurtosis port print luban cl-1-lighthouse-reth http`"
export HELIX_URL="http://`kurtosis port print luban helix-relay api`"
cargo run --bin taiyi preconfer \
  --bls_sk 4942d3308d3fbfbdb977c0bf4c09cb6990aec9fd5ce24709eaf23d96dba71148 \
  --ecdsa_sk 0xc5114526e042343c6d1899cad05e1c00ba588314de9b96929914ee0df18d46b2 \
  --network $WORKING_DIR/el_cl_genesis_data \
  --execution_client_url $EXECUTION_URL \
  --beacon_client_url $BEACON_URL \
  --relay_url $HELIX_URL
