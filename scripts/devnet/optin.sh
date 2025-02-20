set -xe

source "$(dirname "$0")/config.sh"


# get the eigenlayer deploy info 
export STRATEGY_ADDRESS=$(cat contracts/script/output/devnet/local_from_scratch_deployment_data.json | jq -r '.addresses.strategies.WETH')
export STRATEGY_MANAGER_ADDRESS=$(cat contracts/script/output/devnet/local_from_scratch_deployment_data.json | jq -r '.addresses.strategyManager')
export TAIYI_EIGENLAYER_MIDDLEWARE_ADDRESS=$(cat contracts/script/output/devnet/taiyiAddresses.json | jq -r '.taiyiAddresses.eigenLayerMiddleware')
export AVS_DIRECTORY=$(cat contracts/script/output/devnet/local_from_scratch_deployment_data.json | jq -r '.addresses.avsDirectory')
export DELEGATION_MANAGER=$(cat contracts/script/output/devnet/local_from_scratch_deployment_data.json | jq -r '.addresses.delegationManager')
export PRIVATE_KEY="c5114526e042343c6d1899cad05e1c00ba588314de9b96929914ee0df18d46b2"
export OPERATOR_ADDRESS="0xD8F3183DEF51A987222D845be228e0Bbb932C222"
export DELEGATION_APPROVER="0x0000000000000000000000000000000000000000"
export WETH_ADDRESS=$(cat contracts/script/output/devnet/taiyiAddresses.json | jq -r '.taiyiAddresses.weth')
export AMOUNT=1000000000000000000

pushd contracts
echo "convert eth to weth"
cast send $WETH_ADDRESS "deposit()" --value $AMOUNT --rpc-url $EXECUTION_URL --private-key $PRIVATE_KEY

forge script script/Register.s.sol:Register -vvvv  \
    --rpc-url $EXECUTION_URL \
    --broadcast \
    --private-key $PRIVATE_KEY 
popd

# deposit into eigenlayer strategyManager
cargo run --bin taiyi-cli deposit \
    --execution-rpc-url $EXECUTION_URL \
    --strategy-address $STRATEGY_ADDRESS \
    --amount $AMOUNT \
    --private-key $PRIVATE_KEY \
    --strategy-manager-address $STRATEGY_MANAGER_ADDRESS 

# register into eigenlayer middleware
cargo run --bin taiyi-cli register-validator \
    --execution-rpc-url $EXECUTION_URL \
    --private-key $PRIVATE_KEY \
    --salt 0xc31c8871013a7695910115e0e061b769b8168063d9976fb93295e84b05d4a601 \
    --taiyi-avs-address   $TAIYI_EIGENLAYER_MIDDLEWARE_ADDRESS \
    --avs-directory-address $AVS_DIRECTORY 
