set -xe

source "$(dirname "$0")/config.sh"

export AMOUNT=1000000000000000000 # 1ether

export VALIDATOR_OPERATOR_ADDRESS=`cast wallet address --private-key $VALIDATOR_OPERATOR_PRIVATE_KEY`
# register as eigenlayer operator
OPERATOR_PRIVATE_KEY=$VALIDATOR_OPERATOR_PRIVATE_KEY bash scripts/devnet/register-eigenlayer-operator.sh

# stake into eigenlayer
OPERATOR_PRIVATE_KEY=$VALIDATOR_OPERATOR_PRIVATE_KEY OPERATOR_SET_ID=$VALIDATOR_OPERATOR_SET_ID \
    bash scripts/devnet/stake-into-eigenlayer.sh

# register underwriter avs
cargo run --bin taiyi-cli register-for-operator-sets \
    --execution-rpc-url $EXECUTION_URL \
    --operator-set-ids $VALIDATOR_OPERATOR_SET_ID \
    --operator-bls-key $VALIDATOR_BLS_PUBLIC_KEY \
    --private-key $VALIDATOR_OPERATOR_PRIVATE_KEY \
    --allocation-manager-address $ALLOCATION_MANAGER_ADDRESS \
    --avs-address $TAIYI_EIGENLAYER_MIDDLEWARE_ADDRESS \
    --avs-directory-address $AVS_DIRECTORY_ADDRESS \
    --salt 0x0000000000000000000000000000000000000000000000000000000000000000 \
    --socket test-luban

# Count the number of validator keys and create matching number of zero addresses
# cargo run --bin taiyi-cli register-validators \
#     --execution-rpc-url $EXECUTION_URL \
#     --private-key $VALIDATOR_OPERATOR_PRIVATE_KEY \
#     --taiyi-validator-avs-address $TAIYI_VALIDATOR_AVS_ADDRESS \
#     --validator-pubkeys $PRE_REGISTERED_VALIDATOR_KEYS \
#     --pod-owners $POD_OWNERS \
#     --delegated-underwriters "$UNDERWRITER_BLS_PUBLIC_KEY,$UNDERWRITER_BLS_PUBLIC_KEY,$UNDERWRITER_BLS_PUBLIC_KEY,$UNDERWRITER_BLS_PUBLIC_KEY"


# check the stakes of the validators
cargo run --bin taiyi-cli get-strategies-stakes \
    --execution-rpc-url $EXECUTION_URL \
    --operator-address $VALIDATOR_OPERATOR_ADDRESS \
    --validator-avs-address $TAIYI_EIGENLAYER_MIDDLEWARE_ADDRESS