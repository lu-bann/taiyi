set -xe

source "$(dirname "$0")/config.sh"

# `|| true` ignore error to continue even if we did `set -e`
rm -rf linglong || true
kurtosis enclave rm -f $ENCLAVE_NAME
pushd $WORKING_DIR
rm -rf 1-lighthouse-geth-0-63
rm -rf el_cl_genesis_data
popd
