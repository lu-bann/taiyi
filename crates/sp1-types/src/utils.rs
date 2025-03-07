use alloy_sol_types::sol;

sol! {
     /// The public values encoded as a struct that can be easily deserialized inside Solidity.
     struct PublicValuesStruct {
        uint64 proofBlockNumber;
        bytes32 proofBlockHash;
        address gatewayAddress;
        bytes signature;
    }
    function sponsorEthBatch(address[] calldata recipients, uint256[] calldata amounts);
}
