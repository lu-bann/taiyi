use alloy::sol;

sol! {
     /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint64 proofBlockTimestamp;
        bytes32 proofBlockHash;
        uint64 proofBlockNumber;
        address underwriterAddress;
        bytes proofSignature;
        uint64 genesisTimestamp;
        address taiyiCore;
    }
    function sponsorEthBatch(address[] calldata recipients, uint256[] calldata amounts);
}
