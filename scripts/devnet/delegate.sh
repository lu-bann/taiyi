#!/usr/bin/env bash

set -xe

source "$(dirname "$0")/config.sh"

# --fork-version values from crates/cb-common/src/types.rs:
# Mainnet => "0x00000000",
# Holesky => "0x01017000",
# Sepolia => "0x90000069",
# Helder => "0x10000000",
# Hoodi => "0x10000910",

cargo run --bin taiyi-cli delegate \
    --relay-url "$RELAY_URL" \
    --underwriter-pubkey "$UNDERWRITER_BLS_PUBLIC_KEY" \
    --fork-version 0 \
    --action delegate \
    local-keystore \
    --path "$WORKING_DIR/1-lighthouse-geth-0-63/keys" \
    --password-path "$WORKING_DIR/1-lighthouse-geth-0-63/secrets"
