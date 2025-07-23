set -uxeo pipefail

source "$(dirname "$0")/config.sh"

pushd $WORKING_DIR
rm -rf el_cl_genesis_data
rm -rf 1-lighthouse-geth-0-63
kurtosis files download $ENCLAVE_NAME el_cl_genesis_data
kurtosis files download $ENCLAVE_NAME 1-lighthouse-geth-0-63
export GENESIS_TIMESTAMP=`jq -r '.timestamp' ./el_cl_genesis_data/genesis.json`
export PRIVATE_KEY=$TAIYI_CONTRACTS_DEPLOYER_PRIVATE_KEY
export NETWORK="devnet"
popd

# TAIYI propser registry would be 0x0A79920c296E86e7BB12Ad20ca7Ffbbd7AE5905B
# TAIYI CORE would be 0xA791D59427B2b7063050187769AC871B497F4b3C
# make e2e-clean will REMOVE this folder as it is only needed for e2e testing
[ -d "linglong" ] || git clone https://github.com/lu-bann/linglong --recursive --jobs 8 --depth 1
pushd linglong
bash script/deploy.sh
bash script/setup-contract.sh
popd
