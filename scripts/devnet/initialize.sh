set -xe

source "$(dirname "$0")/config.sh"

pushd $WORKING_DIR
rm -rf el_cl_genesis_data
rm -rf 1-lighthouse-reth-0-63-0
kurtosis files download $ENCLAVE_NAME el_cl_genesis_data
kurtosis files download $ENCLAVE_NAME 1-lighthouse-reth-0-63-0
export GENESIS_TIMESTAMP=`jq -r '.timestamp' ./el_cl_genesis_data/genesis.json`
export PRIVATE_KEY="c5114526e042343c6d1899cad05e1c00ba588314de9b96929914ee0df18d46b2"
export NETWORK="devnet"
popd

# TAIYI propser registry would be 0x0A79920c296E86e7BB12Ad20ca7Ffbbd7AE5905B
# TAIYI CORE would be 0xA791D59427B2b7063050187769AC871B497F4b3C
pushd contracts
git submodule update --progress --init
bash script/deploy.sh
popd 