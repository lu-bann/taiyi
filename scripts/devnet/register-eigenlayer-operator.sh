set -xe

source "$(dirname "$0")/config.sh"

export OPERATOR_ADDRESS=`cast wallet address --private-key $OPERATOR_PRIVATE_KEY`

export SELECTOR=`cast sig "setAllocationDelay(address,uint32)"`
# register the operator
cast send -vvvvv --rpc-url $EXECUTION_URL $DELEGATION_MANAGER_ADDRESS \
"registerAsOperator(address,uint32,string)" \
"$OPERATOR_ADDRESS" \
0 \
"tests" \
--private-key $OPERATOR_PRIVATE_KEY

OPERATOR_STATUS=$(cast call -vvvvv --rpc-url $EXECUTION_URL $DELEGATION_MANAGER_ADDRESS \
"isOperator(address)" \
"$OPERATOR_ADDRESS")

if [ "$OPERATOR_STATUS" == "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
    echo "Operator is not registered"
    exit 1
fi
