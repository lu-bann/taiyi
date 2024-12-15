// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;



/// @title BeaconBlockHashVerifierLib
/// @dev `BeaconBlockhashVerifierLib` verifies the integrity of post-Capella
/// blockhashes via SSZ proofs and persists them into the contract's storage.
/// This contract uses the entire storage space of the contract as a
/// mapping between `block.number`s and `blockhash`es. Since each number
/// is unique, this is a safe way to store the verified blockhashes.
/// @custom:attribution https://github.com/axiom-crypto/beacon-blockhash-verifier/blob/main/contracts/src/BeaconBlockhashVerifier.sol
contract BeaconBlockHashVerifierLib {

    uint256 internal constant STATE_ROOT_LOCAL_INDEX = 3;

    /// @dev Index of `block_hash` within the `ExecutionPayload` struct.
    uint256 internal constant BLOCKHASH_LOCAL_INDEX = 12;

    /// @dev The precompile address for SHA-256
    uint256 internal constant SHA256_PRECOMPILE = 0x02;

    /// @dev The address of the EIP-4788 beacon roots contract
    address internal constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @dev Index of `latest_execution_payload_header` within the `BeaconState`
    /// struct.
    uint256 internal constant EXECUTION_PAYLOAD_LOCAL_INDEX = 24;

    /// @dev There are 17 fields in the `ExecutionPayload` struct. So this is
    /// ceil(log_2(17)).
    uint256 constant EXECUTION_PAYLOAD_TREE_HEIGHT = 5;

    /// @dev There are 28 fields in the `BeaconState` struct. So this is
    /// ceil(log_2(28)).
    uint256 constant STATE_ROOT_TREE_HEIGHT = 5;

    /// @dev There are 5 fields in the `BeaconBlock` struct. So this is
    /// ceil(log_2(5)).
    uint256 constant BLOCK_ROOT_TREE_HEIGHT = 3;

    /// @dev Index of `block_number` within the `ExecutionPayload` struct.
    uint256 internal constant BLOCK_NUMBER_LOCAL_INDEX = 6;

    /// @dev Index of the `state_roots` vector within the `BeaconState` struct.
    uint256 internal constant STATE_ROOTS_VECTOR_LOCAL_INDEX = 6;

    /// @dev Height of the `state_roots` Vector within the BeaconState struct.
    /// This is `log_2(8192)` where 8192 is the `SLOTS_PER_HISTORICAL_ROOT`
    /// constant
    uint256 internal constant STATE_ROOTS_VECTOR_TREE_HEIGHT = 13;

    /// @dev Max local index that would be within the `state_roots` vector
    /// (exclusive)
    ///
    /// Just adds the vector capacity
    uint256 internal constant STATE_ROOTS_VECTOR_MAX_LOCAL_INDEX =
        STATE_ROOTS_VECTOR_MIN_LOCAL_INDEX + STATE_ROOTS_VECTOR_NODES;

    /// @dev Amount of leaf nodes in the state roots vector tree. Or, another
    /// way to think of it is that every node at the `BeaconState` layer has
    /// `STATE_ROOTS_VECTOR_NODES` amount of child nodes at the layer where
    /// `state_roots` elements are stored.
    uint256 internal constant STATE_ROOTS_VECTOR_NODES = (1 << STATE_ROOTS_VECTOR_TREE_HEIGHT);

    /// @dev Min local index that would be within the `state_roots` vector
    /// (inclusive)
    ///
    /// We multiply by `STATE_ROOTS_VECTOR_LOCAL_INDEX` to navigate to the
    /// correct subtree.
    uint256 internal constant STATE_ROOTS_VECTOR_MIN_LOCAL_INDEX =
        STATE_ROOTS_VECTOR_NODES * STATE_ROOTS_VECTOR_LOCAL_INDEX;


    struct SszProof {
        bytes32 leaf;
        bytes32[] proof;
    }

    /// @dev Block number verification failed.
    error InvalidBlockNumber();

    /// @dev Blockhash verification failed.
    error InvalidBlockhash();

    /// @dev Execution payload verification failed.
    error InvalidExecutionPayload();


    /// @dev Current state root verification failed.
    error InvalidCurrentStateRoot();

    /// @dev Historical state root verification failed.
    error InvalidHistoricalStateRoot();

    /// @notice Verifies the integrity of a blockhash for a block between `x -
    /// 1` and `x - 8192` (where 8192 comes from the `SLOTS_PER_HISTORICAL_ROOT`
    /// constant) into the beacon block root for block `x`.
    ///
    /// @param timestamp The EIP-4788 timestamp.
    /// @param currentStateRootProof The proof from the `BeaconState` root into
    /// the beacon block root.
    /// @param historicalStateRootProof The proof from the historical state root
    /// (within `state_roots` Vector) into the `BeaconState` root.
    /// @param historicalStateRootLocalIndex The local index of the historical
    /// state root (relative to the `BeaconState` root).
    /// @param executionPayloadProof The proof from the `ExecutionPayload` root
    /// into the `BeaconState` root.
    /// @param blockNumberProof The proof from the execution payload's block
    /// number into the `ExecutionPayload` root. This is used as the index
    /// during persistence of the verified blockhash.
    /// @param blockhashProof The proof from the execution payload's
    /// blockhash into the `ExecutionPayload` root.
    function verifyRecentHistoricalBlock(
        uint256 timestamp,
        SszProof calldata currentStateRootProof,
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex, // Relative to the `BeaconState` root
        SszProof calldata executionPayloadProof,
        SszProof calldata blockNumberProof,
        SszProof calldata blockhashProof
    ) external {
        bytes32 currentSszBlockRoot = _fetchBeaconRoot(timestamp);

        _verifyBeaconStateRoot({ stateRootProof: currentStateRootProof, beaconBlockRoot: currentSszBlockRoot });

        _verifyHistoricalStateRootIntoBeaconStateRoot({
            historicalStateRootProof: historicalStateRootProof,
            historicalStateRootLocalIndex: historicalStateRootLocalIndex,
            beaconStateRoot: currentStateRootProof.leaf
        });

        _verifyExecutionPayload({
            executionPayloadProof: executionPayloadProof,
            beaconStateRoot: historicalStateRootProof.leaf
        });

        _verifyExecutionBlockNumber({
            blockNumberProof: blockNumberProof,
            executionPayloadRoot: executionPayloadProof.leaf
        });

        _verifyExecutionBlockhash({ blockhashProof: blockhashProof, executionPayloadRoot: executionPayloadProof.leaf });

        _storeVerifiedBlockhash(_parseBeBlockNumber(blockNumberProof.leaf), blockhashProof.leaf);
    }


    /// @dev Verifies a `BeaconState` root into a beacon block root.
    ///
    /// @param stateRootProof The proof from the state root into the beacon
    /// block root.
    /// @param beaconBlockRoot The beacon block root to reconcile the proof
    /// against.
    function _verifyBeaconStateRoot(SszProof calldata stateRootProof, bytes32 beaconBlockRoot) internal view {
        if (
            !_processInclusionProofSha256({
                proof: stateRootProof.proof,
                leaf: stateRootProof.leaf,
                localIndex: STATE_ROOT_LOCAL_INDEX,
                root: beaconBlockRoot,
                expectedHeight: BLOCK_ROOT_TREE_HEIGHT
            })
        ) revert InvalidCurrentStateRoot();
    }


    /// @dev Fetches the beacon root for a given L1 block timestamp. The
    /// `l1BlockTimestamp` MUST map to an L1 block. The beacon block root
    /// returned will be that of the block's parent.
    ///
    /// @param l1BlockTimestamp The L1 block timestamp.
    /// @return sszRoot The beacon root belonging to the parent of the block
    /// associated with `l1BlockTimestamp`.
    function _fetchBeaconRoot(uint256 l1BlockTimestamp) internal view returns (bytes32 sszRoot) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, l1BlockTimestamp)
            if iszero(staticcall(gas(), BEACON_ROOTS, 0x00, 0x20, 0x00, 0x20)) {
                mstore(0x00, 0x1aa72f96) // error BeaconRootFetchFailed()
                revert(0x1c, 0x04)
            }
            sszRoot := mload(0x00)
        }
    }

    /// @dev Processes an inclusion proof with a SHA256 hash.
    ///
    /// In case of an invalid proof length, we return false which is to be
    /// handled by the caller.
    ///
    /// In case of a failed SHA-256 call, we revert.
    ///
    /// @param proof The inclusion proof.
    /// @param leaf The leaf to be proven.
    /// @param root The root to reconcile the proof against.
    /// @param localIndex The local index of the leaf.
    /// @param expectedHeight The height of the tree that the proof is for.
    /// @return valid A boolean indicating whether the derived root from the proof
    /// matches the `root` provided.
    function _processInclusionProofSha256(
        bytes32[] calldata proof,
        bytes32 leaf,
        bytes32 root,
        uint256 localIndex,
        uint256 expectedHeight
    ) internal view returns (bool valid) {
        if (proof.length != expectedHeight) return false;

        /// @solidity memory-safe-assembly
        assembly {
            function callSha256(rdataOffset) {
                if iszero(staticcall(gas(), SHA256_PRECOMPILE, 0x00, 0x40, rdataOffset, 0x20)) {
                    mstore(0x00, 0xcd51ef01) // error Sha256CallFailed()
                    revert(0x1c, 0x04)
                }
            }

            switch mod(localIndex, 2)
            case 0 {
                mstore(0x00, leaf)
                mstore(0x20, calldataload(proof.offset))
            }
            default {
                mstore(0x00, calldataload(proof.offset))
                mstore(0x20, leaf)
            }

            // let startOffset := add(proof.offset, 32)
            // But we'll initialize directly in the loop
            let endOffset := add(shl(5, proof.length), proof.offset)
            for { let i := add(proof.offset, 32) } iszero(eq(i, endOffset)) { i := add(i, 32) } {
                // Div by 2
                localIndex := shr(1, localIndex)

                switch mod(localIndex, 2)
                case 0 {
                    // Store returndata at 0x00
                    callSha256(0x00)
                    mstore(0x20, calldataload(i))
                }
                default {
                    // Store returndata at 0x20
                    callSha256(0x20)
                    mstore(0x00, calldataload(i))
                }
            }

            callSha256(0x00)
            let derivedRoot := mload(0x00)

            valid := eq(derivedRoot, root)
        }
    }

    /// @dev Verifies a historical state root into the `BeaconState` root.
    ///
    /// @param historicalStateRootProof The proof from the historical state root
    /// into the `BeaconState` root.
    /// @param historicalStateRootLocalIndex The local index of the historical
    /// state root (relative to the `BeaconState` root).
    /// @param beaconStateRoot The `BeaconState` root to reconcile the proof
    /// against.
    function _verifyHistoricalStateRootIntoBeaconStateRoot(
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex,
        bytes32 beaconStateRoot
    ) internal view {
        // Guarantees that the index is within the `state_roots` vector
        if (
            historicalStateRootLocalIndex < STATE_ROOTS_VECTOR_MIN_LOCAL_INDEX
                || historicalStateRootLocalIndex >= STATE_ROOTS_VECTOR_MAX_LOCAL_INDEX
        ) revert InvalidHistoricalStateRoot();

        if (
            !_processInclusionProofSha256({
                proof: historicalStateRootProof.proof,
                leaf: historicalStateRootProof.leaf,
                root: beaconStateRoot,
                localIndex: historicalStateRootLocalIndex,
                expectedHeight: STATE_ROOT_TREE_HEIGHT + STATE_ROOTS_VECTOR_TREE_HEIGHT
            })
        ) revert InvalidHistoricalStateRoot();
    }

    /// @dev Verifies an `ExecutionPayload` into the `BeaconState` root
    ///
    /// @param executionPayloadProof The proof from the `ExecutionPayload` root
    /// into the `BeaconState` root.
    /// @param beaconStateRoot The `BeaconState` root to reconcile the proof
    /// against.
    function _verifyExecutionPayload(SszProof calldata executionPayloadProof, bytes32 beaconStateRoot) internal view {
        if (
            !_processInclusionProofSha256({
                proof: executionPayloadProof.proof,
                leaf: executionPayloadProof.leaf,
                root: beaconStateRoot,
                localIndex: EXECUTION_PAYLOAD_LOCAL_INDEX,
                expectedHeight: EXECUTION_PAYLOAD_TREE_HEIGHT
            })
        ) revert InvalidExecutionPayload();
    }

    /// @dev Verifies a block number into an `ExecutionPayload` root
    ///
    /// @param blockNumberProof The proof from the execution payload's block
    /// number into the `ExecutionPayload` root.
    /// @param executionPayloadRoot The `ExecutionPayload` root to reconcile the proof against.
    function _verifyExecutionBlockNumber(SszProof calldata blockNumberProof, bytes32 executionPayloadRoot)
        internal
        view
    {
        if (
            !_processInclusionProofSha256({
                proof: blockNumberProof.proof,
                leaf: blockNumberProof.leaf,
                root: executionPayloadRoot,
                localIndex: BLOCK_NUMBER_LOCAL_INDEX,
                expectedHeight: EXECUTION_PAYLOAD_TREE_HEIGHT
            })
        ) revert InvalidBlockNumber();
    }

    /// @dev Verifies a blockhash into an `ExecutionPayload` root
    ///
    /// @param blockhashProof The proof from the execution payload's blockhash
    /// into the `ExecutionPayload` root.
    /// @param executionPayloadRoot The `ExecutionPayload` root to reconcile the proof against.
    function _verifyExecutionBlockhash(SszProof calldata blockhashProof, bytes32 executionPayloadRoot) internal view {
        if (
            !_processInclusionProofSha256({
                proof: blockhashProof.proof,
                leaf: blockhashProof.leaf,
                root: executionPayloadRoot,
                localIndex: BLOCKHASH_LOCAL_INDEX,
                expectedHeight: EXECUTION_PAYLOAD_TREE_HEIGHT
            })
        ) revert InvalidBlockhash();
    }

    /// @dev This contract uses the entire storage space of the contract as a
    /// mapping between `block.number`s and `blockhash`es. Since each number
    /// is unique, this is a safe way to store the verified blockhashes.
    ///
    /// @param blockNumber The block number to map the `_blockhash` into
    /// @param _blockhash The blockhash to store
    function _storeVerifiedBlockhash(uint256 blockNumber, bytes32 _blockhash) internal {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(blockNumber, _blockhash)
        }
    }

    /// @notice Parses a big-endian formatted block number
    /// @dev This only parses the first 6 bytes since a uint48 is enough to
    /// encode a block number.
    ///
    /// @param beBlockNumber The big-endian formatted block number
    /// @return blockNumber The parsed block number
    function _parseBeBlockNumber(bytes32 beBlockNumber) internal pure returns (uint256 blockNumber) {
        /// @solidity memory-safe-assembly
        assembly {
            blockNumber := or(blockNumber, byte(0, beBlockNumber))
            blockNumber := or(blockNumber, shl(8, byte(1, beBlockNumber)))
            blockNumber := or(blockNumber, shl(16, byte(2, beBlockNumber)))
            blockNumber := or(blockNumber, shl(24, byte(3, beBlockNumber)))
            blockNumber := or(blockNumber, shl(32, byte(4, beBlockNumber)))
            blockNumber := or(blockNumber, shl(40, byte(5, beBlockNumber)))
        }
    }


}