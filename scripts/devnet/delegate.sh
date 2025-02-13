set -xe

source "$(dirname "$0")/config.sh"

cargo run --bin taiyi-cli delegate \
    --relay-url $RELAY_URL \
    --gateway-pubkey $GATEWAY_BLS_PUBLIC_KEY \
    --network $WORKING_DIR/el_cl_genesis_data \
    --action delegate \
    local-keystore \
    --path $WORKING_DIR/1-lighthouse-reth-0-63-0/keys \
    --password-path $WORKING_DIR/1-lighthouse-reth-0-63-0/secrets
