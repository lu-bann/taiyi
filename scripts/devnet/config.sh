set -x

# set default enclave name
if [ -z "$ENCLAVE_NAME" ]; then
  export ENCLAVE_NAME="luban"
fi

if [ -z "$WORKING_DIR" ]; then
  export WORKING_DIR="$(pwd)"
fi

source .env.ci

# Source .env file if it exists
# override local env variables
if [ -f .env ]; then
    source .env
fi


if kurtosis enclave inspect $ENCLAVE_NAME >/dev/null 2>&1; then
  export EXECUTION_URL="http://$(kurtosis port print luban el-1-reth-lighthouse rpc)"
  export BEACON_URL="$(kurtosis port print luban cl-1-lighthouse-reth http)"
  export RELAY_URL="http://$(kurtosis port print luban helix-relay api)"
fi

# Read deployment data if file exists
EIGENLAYER_DEPLOYMENT_FILE="contracts/script/output/devnet/M2_from_scratch_deployment_data.json"
if [ -f "$EIGENLAYER_DEPLOYMENT_FILE" ]; then
    export DELEGATION_MANAGER_ADDRESS=$(jq -r '.addresses.delegationManager' "$EIGENLAYER_DEPLOYMENT_FILE")
    export STRATEGY_MANAGER_ADDRESS=$(jq -r '.addresses.strategyManager' "$EIGENLAYER_DEPLOYMENT_FILE")
    export AVS_DIRECTORY_ADDRESS=$(jq -r '.addresses.avsDirectory' "$EIGENLAYER_DEPLOYMENT_FILE")
    export PERMISSION_CONTROLLER_ADDRESS=$(jq -r '.addresses.permissionController' "$EIGENLAYER_DEPLOYMENT_FILE")
    export ALLOCATION_MANAGER_ADDRESS=$(jq -r '.addresses.allocationManager' "$EIGENLAYER_DEPLOYMENT_FILE")
    export WETH_STRATEGY_ADDRESS=$(jq -r '.addresses.strategies.WETH' "$EIGENLAYER_DEPLOYMENT_FILE")
fi

TAIYI_DEPLOYMENT_FILE="contracts/script/output/devnet/taiyiAddresses.json"
if [ -f "$TAIYI_DEPLOYMENT_FILE" ]; then
    export WETH_ADDRESS=$(jq -r '.taiyiAddresses.weth' "$TAIYI_DEPLOYMENT_FILE")
    export TAIYI_GATEWAY_AVS_ADDRESS=$(jq -r '.taiyiAddresses.gatewayAVSProxy' "$TAIYI_DEPLOYMENT_FILE")
    export TAIYI_VALIDATOR_AVS_ADDRESS=$(jq -r '.taiyiAddresses.validatorAVSProxy' "$TAIYI_DEPLOYMENT_FILE")
    export TAIYI_CORE_ADDRESS=$(jq -r '.taiyiAddresses.taiyiCoreProxy' "$TAIYI_DEPLOYMENT_FILE")
    export TAIYI_PROPOSER_REGISTRY_ADDRESS=$(jq -r '.taiyiAddresses.taiyiProposerRegistryProxy' "$TAIYI_DEPLOYMENT_FILE")
fi
