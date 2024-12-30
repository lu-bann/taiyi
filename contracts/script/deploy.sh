if [ -z "$EXECUTION_URL" ]; then
    export EXECUTION_URL="http://localhost:8545"
fi
forge script --rpc-url $EXECUTION_URL -vvvv --private-key $PRIVATE_KEY --broadcast ./script/Deployments.s.sol:Deploy