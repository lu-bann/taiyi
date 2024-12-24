set -xe

source "$(dirname "$0")/config.sh"

export GATEWAY_PUBKEY="a6767d972d21a17843ea94da59461a04d8d0baf92f7c518653170e708f4b21d537db56f9b73810252e0f4e99cc9184cb"

cargo run --bin taiyi-cli delegate \
    --relay-url $RELAY_URL \
    --gateway-pubkey $GATEWAY_PUBKEY \
    --network $WORKING_DIR/el_cl_genesis_data \
    --action delegate \
    local-keystore \
    --path $WORKING_DIR/1-lighthouse-reth-0-63-0/keys \
    --password-path $WORKING_DIR/1-lighthouse-reth-0-63-0/secrets
