set -xe

source "$(dirname "$0")/config.sh"

if kurtosis enclave inspect $ENCLAVE_NAME >/dev/null 2>&1; then
  export EXECUTION_CLIENT_WS_URL="ws://`kurtosis port print luban el-1-geth-lighthouse ws`"
  export BEACON_URL="`kurtosis port print luban cl-1-lighthouse-geth http`"
fi

# TAIYI_DEPLOYMENT_FILE="contracts/script/output/devnet/taiyiAddresses.json"
# if [ -f "$TAIYI_DEPLOYMENT_FILE" ]; then
#     export TAIYI_CHALLENGER_ADDRESS=$(jq -r '.taiyiAddresses.taiyiChallengerProxy' "$TAIYI_DEPLOYMENT_FILE")
# fi

export TAIYI_CHALLENGER_ADDRESS=0x0000000000000000000000000000000000000000

cargo run --bin taiyi-challenger -- \
  --execution-client-ws-url $EXECUTION_CLIENT_WS_URL \
  --beacon-url $BEACON_URL \
  --finalization-window 32 \
  --underwriter-stream-urls http://127.0.0.1:5656/commitments/v0/commitment_stream \
  --private-key 0xbf3beef3bd999ba9f2451e06936f0423cd62b815c9233dd3bc90f7e02a1e8673 \
  --taiyi-challenger-address $TAIYI_CHALLENGER_ADDRESS
