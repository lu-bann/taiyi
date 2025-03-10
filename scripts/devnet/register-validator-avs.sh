set -xe

source "$(dirname "$0")/config.sh"

export AMOUNT=1000000000000000000 # 1ether

export VALIDATOR_OPERATOR_ADDRESS=`cast wallet address --private-key $VALIDATOR_OPERATOR_PRIVATE_KEY`
# register as eigenlayer operator
OPERATOR_PRIVATE_KEY=$VALIDATOR_OPERATOR_PRIVATE_KEY bash scripts/devnet/register-eigenlayer-operator.sh

# convert eth to WETH
cast send -vvvvv --rpc-url $EXECUTION_URL $WETH_ADDRESS \
    "deposit()" \
    --value 10ether \
    --private-key $VALIDATOR_OPERATOR_PRIVATE_KEY

# # deposit 1000000000000000000 to the strategy
cargo run --bin taiyi-cli deposit \
    --execution-rpc-url $EXECUTION_URL \
    --strategy-address $WETH_STRATEGY_ADDRESS \
    --amount $AMOUNT \
    --private-key $VALIDATOR_OPERATOR_PRIVATE_KEY \
    --strategy-manager-address $STRATEGY_MANAGER_ADDRESS

# register validator in taiyi validator avs 
cargo run --bin taiyi-cli register-validator-avs \
    --execution-rpc-url $EXECUTION_URL \
    --salt 0x0000000000000000000000000000000000000000000000000000000000000000 \
    --avs-directory-address $AVS_DIRECTORY_ADDRESS \
    --taiyi-avs-address $TAIYI_VALIDATOR_AVS_ADDRESS \
    --private-key $VALIDATOR_OPERATOR_PRIVATE_KEY 

OPERATOR_STATUS=$(cargo run --bin taiyi-cli operator-info \
    --execution-rpc-url $EXECUTION_URL \
    --operator-address $VALIDATOR_OPERATOR_ADDRESS \
    --proposer-registry-address $TAIYI_PROPOSER_REGISTRY_ADDRESS \
    --avs-type validator)

if ! echo "$OPERATOR_STATUS" | grep -q "Is Active: true"; then
    echo "Operator is not active in gateway AVS"
    exit 1
fi

# Count the number of validator keys and create matching number of zero addresses
cargo run --bin taiyi-cli register-validators \
    --execution-rpc-url $EXECUTION_URL \
    --private-key $VALIDATOR_OPERATOR_PRIVATE_KEY \
    --taiyi-validator-avs-address $TAIYI_VALIDATOR_AVS_ADDRESS \
    --validator-pubkeys $PRE_REGISTERED_VALIDATOR_KEYS \
    --pod-owners $POD_OWNERS \
    --delegated-gateways "$GATEWAY_BLS_PUBLIC_KEY,$GATEWAY_BLS_PUBLIC_KEY,$GATEWAY_BLS_PUBLIC_KEY,$GATEWAY_BLS_PUBLIC_KEY"


# check whether the validators are registered in taiyi validator avs
cargo run --bin taiyi-cli get-validators-for-operators \
    --execution-rpc-url $EXECUTION_URL \
    --operator-address $VALIDATOR_OPERATOR_ADDRESS \
    --proposer-registry-address $TAIYI_PROPOSER_REGISTRY_ADDRESS


# check the stakes of the validators
cargo run --bin taiyi-cli get-strategies-stakes \
    --execution-rpc-url $EXECUTION_URL \
    --operator-address $VALIDATOR_OPERATOR_ADDRESS \
    --validator-avs-address $TAIYI_VALIDATOR_AVS_ADDRESS

