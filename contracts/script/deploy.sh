if [ -z "$EXECUTION_URL" ]; then
    export EXECUTION_URL="http://localhost:8545"
    export PRIVATE_KEY="c5114526e042343c6d1899cad05e1c00ba588314de9b96929914ee0df18d46b2"
fi
forge script --rpc-url $EXECUTION_URL -vvvv --private-key $PRIVATE_KEY --broadcast ./script/Deployments.s.sol:Deploy