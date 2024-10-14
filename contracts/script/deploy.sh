if [ -z "$RPC_URL" ]; then
    export RPC_URL="http://localhost:8545"
fi
forge script --rpc-url $RPC_URL -vvvv --private-key $PRIVATE_KEY --broadcast ./script/DeploymentsHelder.s.sol:DeployHelder
