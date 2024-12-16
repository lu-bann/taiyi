set -xe
# set default enclave name
source "$(dirname "$0")/config.sh"


pushd $WORKING_DIR
kurtosis run --enclave $ENCLAVE_NAME github.com/lu-bann/ethereum-package@taiyi --args-file scripts/devnet/luban.yml
popd