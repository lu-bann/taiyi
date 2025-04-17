set -xe

source "$(dirname "$0")/config.sh"

# register as eigenlayer operator
OPERATOR_PRIVATE_KEY=$UNDERWRITER_ECDSA_PRIVATE_KEY bash scripts/devnet/register-eigenlayer-operator.sh

export OPERATOR_ADDRESS=`cast wallet address --private-key $UNDERWRITER_ECDSA_PRIVATE_KEY`

# register underwriter avs
cargo run --bin taiyi-cli register-underwriter-avs \
    --execution-rpc-url $EXECUTION_URL \
    --underwriter-avs-address $TAIYI_UNDERWRITER_AVS_ADDRESS \
    --operator-bls-key $UNDERWRITER_BLS_PUBLIC_KEY \
    --private-key $UNDERWRITER_ECDSA_PRIVATE_KEY \
    --salt 0x0000000000000000000000000000000000000000000000000000000000000000 \
    --avs-directory-address $AVS_DIRECTORY_ADDRESS


# check whether the operator is in underwriter avs
OPERATOR_STATUS=$(cargo run --bin taiyi-cli operator-info \
    --execution-rpc-url $EXECUTION_URL \
    --operator-address $OPERATOR_ADDRESS \
    --proposer-registry-address $TAIYI_PROPOSER_REGISTRY_ADDRESS \
    --avs-type underwriter)

if ! echo "$OPERATOR_STATUS" | grep -q "Is Active: true"; then
    echo "Operator is not active in underwriter AVS"
    exit 1
fi
