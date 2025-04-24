set -xe

source "$(dirname "$0")/config.sh"

export OPERATOR_ADDRESS=`cast wallet address --private-key $OPERATOR_PRIVATE_KEY`

# wrap eth to weth 
cast send --rpc-url $EXECUTION_URL $WETH_ADDRESS  --value 1000000000000000000 \
    --private-key $OPERATOR_PRIVATE_KEY

# approve weth to be spent by eigenlayer
cast send --rpc-url $EXECUTION_URL $WETH_ADDRESS \
    "approve(address,uint256)" \
    $STRATEGY_MANAGER_ADDRESS \
    1000000000000000000 \
    --private-key $OPERATOR_PRIVATE_KEY

# stake into eigenlayer
cast send --rpc-url $EXECUTION_URL $STRATEGY_MANAGER_ADDRESS \
    "depositIntoStrategy(address,address,uint256)" \
    $WETH_STRATEGY_ADDRESS \
    $WETH_ADDRESS \
    1000000000000000000 \
    --private-key $OPERATOR_PRIVATE_KEY

# set allocation delay 
cast send --rpc-url $EXECUTION_URL $ALLOCATION_MANAGER_ADDRESS \
    "setAllocationDelay(address,uint32)" \
    $OPERATOR_ADDRESS \
    1 \
    --private-key $OPERATOR_PRIVATE_KEY

# allocate stake to operator set 
cast send --rpc-url $EXECUTION_URL $ALLOCATION_MANAGER_ADDRESS \
    "modifyAllocations(address,((address,uint32),address[],uint64[])[])" \
    $OPERATOR_ADDRESS \
    "[(($TAIYI_EIGENLAYER_MIDDLEWARE_ADDRESS, $UNDERWRITER_OPERATOR_SET_ID),[$WETH_STRATEGY_ADDRESS], [1000000000000000000])]" \
    --private-key $OPERATOR_PRIVATE_KEY
