set -xe

source "$(dirname "$0")/config.sh"

cargo run --bin taiyi-cli delegate \
    --relay-url $RELAY_URL \
    --underwriter-pubkey $UNDERWRITER_BLS_PUBLIC_KEY \
    --network $WORKING_DIR/el_cl_genesis_data \
    --action delegate \
    local-keystore \
    --path $WORKING_DIR/1-lighthouse-geth-0-63/keys \
    --password-path $WORKING_DIR/1-lighthouse-geth-0-63/secrets
