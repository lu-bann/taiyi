set -xe
# set default enclave name
source "$(dirname "$0")/config.sh"

if [ -z "$TAIYI_BOOST_IMAGE" ]; then
  export TAIYI_BOOST_IMAGE="lubann/taiyi:latest"
fi

sed -i "s|lubann/taiyi:latest|${TAIYI_BOOST_IMAGE}|g" scripts/devnet/luban.yml

pushd $WORKING_DIR
kurtosis run --enclave $ENCLAVE_NAME github.com/lu-bann/ethereum-package@taiyi --args-file scripts/devnet/luban.yml
popd