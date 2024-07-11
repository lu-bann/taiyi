if [ -z "$RPC_URL" ]; then
    export RPC_URL="http://localhost:8545"
fi
forge script --rpc-url $RPC_URL -vvvv --private-key $PRIVATE --broadcast script/DeploymentsDevnet.s.sol
