set -xe

source "$(dirname "$0")/config.sh"

kurtosis enclave rm -f $ENCLAVE_NAME
pushd $WORKING_DIR
rm -rf 1-lighthouse-reth-0-63-0
rm -rf el_cl_genesis_data
popd
