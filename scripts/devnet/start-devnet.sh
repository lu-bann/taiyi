set -xe
# set default enclave name
source "$(dirname "$0")/config.sh"

export TAIYI_BOOST_IMAGE="${TAIYI_BOOST_IMAGE:-lubann/taiyi:latest}"

if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS (Darwin)
  sed -i '' "s|lubann/taiyi:latest|${TAIYI_BOOST_IMAGE}|g" scripts/devnet/luban.yml
else
  # Linux and others
  sed -i "s|lubann/taiyi:latest|${TAIYI_BOOST_IMAGE}|g" scripts/devnet/luban.yml
fi

cat scripts/devnet/luban.yml
pushd $WORKING_DIR
kurtosis run --enclave $ENCLAVE_NAME github.com/lu-bann/ethereum-package@taiyi --args-file scripts/devnet/luban.yml
popd
