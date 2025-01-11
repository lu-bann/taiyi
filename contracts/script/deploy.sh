if [ -z "$EXECUTION_URL" ]; then
    export EXECUTION_URL="http://localhost:8545"
fi
export FOUNDRY_PROFILE=prod
forge script --rpc-url $EXECUTION_URL \
-vvvv --private-key $PRIVATE_KEY --broadcast ./script/Deployments.s.sol:Deploy \
--sig "run(string memory configFile)" \
-- eigenlayer-deploy-config-devnet.json
