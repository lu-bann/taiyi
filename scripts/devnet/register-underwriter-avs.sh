set -xe

source "$(dirname "$0")/config.sh"

# register as eigenlayer operator
OPERATOR_PRIVATE_KEY=$UNDERWRITER_ECDSA_PRIVATE_KEY bash scripts/devnet/register-eigenlayer-operator.sh

# stake into eigenlayer
OPERATOR_PRIVATE_KEY=$UNDERWRITER_ECDSA_PRIVATE_KEY bash scripts/devnet/stake-into-eigenlayer.sh

export OPERATOR_ADDRESS=`cast wallet address --private-key $UNDERWRITER_ECDSA_PRIVATE_KEY`

# register underwriter avs
cargo run --bin taiyi-cli register-for-operator-sets \
    --execution-rpc-url $EXECUTION_URL \
    --operator-set-ids $UNDERWRITER_OPERATOR_SET_ID \
    --operator-bls-key $UNDERWRITER_BLS_PUBLIC_KEY \
    --private-key $UNDERWRITER_ECDSA_PRIVATE_KEY \
    --allocation-manager-address $ALLOCATION_MANAGER_ADDRESS \
    --avs-address $TAIYI_EIGENLAYER_MIDDLEWARE_ADDRESS \
    --socket test-luban

# check whether the operator is in underwriter avs
# OPERATOR_STATUS=$(cargo run --bin taiyi-cli operator-info \
#     --execution-rpc-url $EXECUTION_URL \
#     --operator-address $OPERATOR_ADDRESS \
#     --proposer-registry-address $TAIYI_PROPOSER_REGISTRY_ADDRESS \
#     --avs-type underwriter)
