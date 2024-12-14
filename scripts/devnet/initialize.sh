set -xe

source "$(dirname "$0")/config.sh"


pushd $WORKING_DIR
rm -rf el_cl_genesis_data
rm -rf 1-lighthouse-reth-0-63-0
kurtosis files download luban el_cl_genesis_data
kurtosis files download luban 1-lighthouse-reth-0-63-0
export GENESIS_TIMESTAMP=`jq -r '.timestamp' ./el_cl_genesis_data/genesis.json`
popd

# TAIYI propser registry would be 0x0A79920c296E86e7BB12Ad20ca7Ffbbd7AE5905B
# TAIYI CORE would be 0xA791D59427B2b7063050187769AC871B497F4b3C
if [ "$(cast code 0x0A79920c296E86e7BB12Ad20ca7Ffbbd7AE5905B --rpc-url $EXECUTION_URL)" == "0x" ]; then
    pushd contracts
    PRIVATE_KEY="c5114526e042343c6d1899cad05e1c00ba588314de9b96929914ee0df18d46b2" \
    bash script/deploy.sh
    popd 
fi
