// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Libraries
import { LibBytes } from "./LibBytes.sol";
import { RLPReaderLib } from "./RLPReaderLib.sol";
import { RLPItem, RLPItemType, LibMemory } from "./LibMemory.sol";

/// @title MerkleTrie
/// @notice MerkleTrie is a small library for verifying standard Ethereum Merkle-Patricia trie
///         inclusion proofs. By default, this library assumes a hexary trie. One can change the
///         trie radix constant to support other trie radixes.
/// @custom:attribution Based on
/// https://github.com/ethereum-optimism/optimism/blob/2b589dfd0bfe371f99dcab24f21ff9dd60938561/packages/contracts-bedrock/src/libraries/trie/MerkleTrie.sol
library MerkleTrie {
    /// @notice Struct representing a node in the trie.
    /// @custom:field encoded The RLP-encoded node.
    /// @custom:field decoded The RLP-decoded node.
    struct TrieNode {
        bytes encoded;
        RLPItem[] decoded;
    }

    bytes1 constant RLP_NULL = bytes1(0x80);

    /// @notice Determines the number of elements per branch node.
    uint256 internal constant TREE_RADIX = 16;

    /// @notice Branch nodes have TREE_RADIX elements and one value element.
    uint256 internal constant BRANCH_NODE_LENGTH = TREE_RADIX + 1;

    /// @notice Leaf nodes and extension nodes have two elements, a `path` and a `value`.
    uint256 internal constant LEAF_OR_EXTENSION_NODE_LENGTH = 2;

    /// @notice Prefix for even-nibbled extension node paths.
    uint8 internal constant PREFIX_EXTENSION_EVEN = 0;

    /// @notice Prefix for odd-nibbled extension node paths.
    uint8 internal constant PREFIX_EXTENSION_ODD = 1;

    /// @notice Prefix for even-nibbled leaf node paths.
    uint8 internal constant PREFIX_LEAF_EVEN = 2;

    /// @notice Prefix for odd-nibbled leaf node paths.
    uint8 internal constant PREFIX_LEAF_ODD = 3;

    /// @notice Verifies a proof that a given key/value pair is present in the trie.
    /// @param _key   Key of the node to search for, as a hex string.
    /// @param _value Value of the node to search for, as a hex string.
    /// @param _proof Merkle trie inclusion proof for the desired node. Unlike traditional Merkle
    ///               trees, this proof is executed top-down and consists of a list of RLP-encoded
    ///               nodes that make a path down to the target node.
    /// @param _root  Known root of the Merkle trie. Used to verify that the included proof is
    ///               correctly constructed.
    /// @return valid_ Whether or not the proof is valid.
    function verifyInclusionProof(
        bytes memory _key,
        bytes memory _value,
        bytes[] memory _proof,
        bytes32 _root
    )
        internal
        view
        returns (bool valid_)
    {
        valid_ = LibBytes.equal(_value, get(_key, _proof, _root));
    }

    function get(bytes memory _key, bytes32 _root) public view returns (bool _exists, bytes memory _value) {
        (TrieNode[] memory proof, uint256 pathLength, bytes memory keyRemainder, bool isFinalNode) =
            _walkNodePath(_key, _root);

        bool exists = keyRemainder.length == 0;

        require(exists || isFinalNode, "Provided proof is invalid.");

        bytes memory value = exists ? _getNodeValue(proof[pathLength - 1]) : bytes("");

        return (exists, value);
    }

    /// @notice Retrieves the value associated with a given key.
    /// @param _key   Key to search for, as hex bytes.
    /// @param _proof Merkle trie inclusion proof for the key.
    /// @param _root  Known root of the Merkle trie.
    /// @return value_ Value of the key if it exists.
    function get(bytes memory _key, bytes[] memory _proof, bytes32 _root) public view returns (bytes memory value_) {
        require(_key.length > 0, "MerkleTrie: empty key");

        TrieNode[] memory proof = _parseProof(_proof);
        bytes memory key = LibBytes.toNibbles(_key);
        bytes memory currentNodeID = abi.encodePacked(_root);
        uint256 currentNodeLength = 32;
        uint256 currentKeyIndex = 0;

        // Proof is top-down, so we start at the first element (root).
        for (uint256 i = 0; i < proof.length; i++) {
            TrieNode memory currentNode = proof[i];

            // Key index should never exceed total key length or we'll be out of bounds.
            require(currentKeyIndex <= key.length, "MerkleTrie: key index exceeds total key length");

            if (currentKeyIndex == 0) {
                // First proof element is always the root node.
                require(
                    LibBytes.equal(abi.encodePacked(keccak256(currentNode.encoded)), currentNodeID),
                    "MerkleTrie: invalid root hash"
                );
            } else if (currentNode.encoded.length >= 32) {
                // Nodes 32 bytes or larger are hashed inside branch nodes.
                require(
                    LibBytes.equal(abi.encodePacked(keccak256(currentNode.encoded)), currentNodeID),
                    "MerkleTrie: invalid large internal hash"
                );
            } else {
                // Nodes smaller than 32 bytes aren't hashed.
                require(LibBytes.equal(currentNode.encoded, currentNodeID), "MerkleTrie: invalid internal node hash");
            }

            if (currentNode.decoded.length == BRANCH_NODE_LENGTH) {
                if (currentKeyIndex == key.length) {
                    // Value is the last element of the decoded list (for branch nodes). There's
                    // some ambiguity in the Merkle trie specification because bytes(0) is a
                    // valid value to place into the trie, but for branch nodes bytes(0) can exist
                    // even when the value wasn't explicitly placed there. Geth treats a value of
                    // bytes(0) as "key does not exist" and so we do the same.
                    value_ = RLPReaderLib.readBytes(currentNode.decoded[TREE_RADIX]);
                    require(value_.length > 0, "MerkleTrie: value length must be greater than zero (branch)");

                    // Extra proof elements are not allowed.
                    require(i == proof.length - 1, "MerkleTrie: value node must be last node in proof (branch)");

                    return value_;
                } else {
                    // We're not at the end of the key yet.
                    // Figure out what the next node ID should be and continue.
                    uint8 branchKey = uint8(key[currentKeyIndex]);
                    RLPItem nextNode = currentNode.decoded[branchKey];
                    bytes32 nextNodeId;
                    (nextNodeId, currentNodeLength) = _getNodeID(nextNode);
                    currentNodeID = abi.encodePacked(nextNodeId);
                    currentKeyIndex += 1;
                }
            } else if (currentNode.decoded.length == LEAF_OR_EXTENSION_NODE_LENGTH) {
                bytes memory path = _getNodePath(currentNode);
                uint8 prefix = uint8(path[0]);
                uint8 offset = 2 - (prefix % 2);
                bytes memory pathRemainder = LibBytes.slice(path, offset);
                bytes memory keyRemainder = LibBytes.slice(key, currentKeyIndex);
                uint256 sharedNibbleLength = _getSharedNibbleLength(pathRemainder, keyRemainder);

                // Whether this is a leaf node or an extension node, the path remainder MUST be a
                // prefix of the key remainder (or be equal to the key remainder) or the proof is
                // considered invalid.
                require(
                    pathRemainder.length == sharedNibbleLength,
                    "MerkleTrie: path remainder must share all nibbles with key"
                );

                if (prefix == PREFIX_LEAF_EVEN || prefix == PREFIX_LEAF_ODD) {
                    // Prefix of 2 or 3 means this is a leaf node. For the leaf node to be valid,
                    // the key remainder must be exactly equal to the path remainder. We already
                    // did the necessary byte comparison, so it's more efficient here to check that
                    // the key remainder length equals the shared nibble length, which implies
                    // equality with the path remainder (since we already did the same check with
                    // the path remainder and the shared nibble length).
                    require(
                        keyRemainder.length == sharedNibbleLength,
                        "MerkleTrie: key remainder must be identical to path remainder"
                    );

                    // Our Merkle Trie is designed specifically for the purposes of the Ethereum
                    // state trie. Empty values are not allowed in the state trie, so we can safely
                    // say that if the value is empty, the key should not exist and the proof is
                    // invalid.
                    value_ = RLPReaderLib.readBytes(currentNode.decoded[1]);
                    require(value_.length > 0, "MerkleTrie: value length must be greater than zero (leaf)");

                    // Extra proof elements are not allowed.
                    require(i == proof.length - 1, "MerkleTrie: value node must be last node in proof (leaf)");

                    return value_;
                } else if (prefix == PREFIX_EXTENSION_EVEN || prefix == PREFIX_EXTENSION_ODD) {
                    // Prefix of 0 or 1 means this is an extension node. We move onto the next node
                    // in the proof and increment the key index by the length of the path remainder
                    // which is equal to the shared nibble length.
                    bytes32 nextNodeId;
                    (nextNodeId, currentNodeLength) = _getNodeID(currentNode.decoded[1]);
                    currentNodeID = abi.encodePacked(nextNodeId);
                    currentKeyIndex += sharedNibbleLength;
                } else {
                    revert("MerkleTrie: received a node with an unknown prefix");
                }
            } else {
                revert("MerkleTrie: received an unparseable node");
            }
        }

        revert("MerkleTrie: ran out of proof elements");
    }

    /// @notice Parses an array of proof elements into a new array that contains both the original
    ///         encoded element and the RLP-decoded element.
    /// @param _proof Array of proof elements to parse.
    /// @return proof_ Proof parsed into easily accessible structs.
    function _parseProof(bytes[] memory _proof) private pure returns (TrieNode[] memory proof_) {
        uint256 length = _proof.length;
        proof_ = new TrieNode[](length);
        for (uint256 i = 0; i < length;) {
            proof_[i] = TrieNode({ encoded: _proof[i], decoded: RLPReaderLib.readList(_proof[i]) });
            unchecked {
                ++i;
            }
        }
    }


    /**
     * @notice Picks out the ID for a node. Node ID is referred to as the
     * "hash" within the specification, but nodes < 32 bytes are not actually
     * hashed.
     * @param _node Node to pull an ID for.
     * @return _nodeID ID for the node, depending on the size of its contents.
     */
    function _getNodeID(
        RLPItem _node
    )
        private
        pure
        returns (
            bytes32 _nodeID,
            uint256 length
        )
    {
        bytes memory nodeID;

        if (_node.length() < 32) {
            // Nodes smaller than 32 bytes are RLP encoded.
            nodeID = RLPReaderLib.readRawBytes(_node);
        } else {
            // Nodes 32 bytes or larger are hashed.
            nodeID = RLPReaderLib.readBytes(_node);
        }

        return (LibBytes.toBytes32(nodeID), _node.length());
    }

    /// @notice Gets the path for a leaf or extension node.
    /// @param _node Node to get a path for.
    /// @return nibbles_ Node path, converted to an array of nibbles.
    function _getNodePath(TrieNode memory _node) private pure returns (bytes memory nibbles_) {
        nibbles_ = LibBytes.toNibbles(RLPReaderLib.readBytes(_node.decoded[0]));
    }

    /// @notice Utility; determines the number of nibbles shared between two nibble arrays.
    /// @param _a First nibble array.
    /// @param _b Second nibble array.
    /// @return shared_ Number of shared nibbles.
    function _getSharedNibbleLength(bytes memory _a, bytes memory _b) private pure returns (uint256 shared_) {
        uint256 max = (_a.length < _b.length) ? _a.length : _b.length;
        for (; shared_ < max && _a[shared_] == _b[shared_];) {
            unchecked {
                ++shared_;
            }
        }
    }

    /**
     * @notice Walks through a proof using a provided key.
     * @param _key Key to use for the walk.
     * @param _root Known root of the trie.
     * @return _proof The proof
     * @return _pathLength Length of the final path
     * @return _keyRemainder Portion of the key remaining after the walk.
     * @return _isFinalNode Whether or not we've hit a dead end.
     */
    function _walkNodePath(
        bytes memory _key,
        bytes32 _root
    )
        private
        view
        returns (TrieNode[] memory _proof, uint256 _pathLength, bytes memory _keyRemainder, bool _isFinalNode)
    {
        // TODO: this is max length
        _proof = new TrieNode[](9);

        uint256 pathLength = 0;
        bytes memory key = LibBytes.toNibbles(_key);

        bytes32 currentNodeID = _root;
        uint256 currentNodeLength = 32;
        uint256 currentKeyIndex = 0;
        uint256 currentKeyIncrement = 0;
        TrieNode memory currentNode;

        // Proof is top-down, so we start at the first element (root).
        for (uint256 i = 0; i < _proof.length; i++) {
            if (currentNodeID == bytes32(RLP_NULL)) {
                break;
            }
            if (currentNodeLength >= 32) {
                currentNode = getTrieNode(currentNodeID);
            } else {
                currentNode = getRawNode(LibBytes.slice(abi.encodePacked(currentNodeID), 0, currentNodeLength));
            }
            _proof[pathLength] = currentNode;
            currentKeyIndex += currentKeyIncrement;

            // Keep track of the proof elements we actually need.
            // It's expensive to resize arrays, so this simply reduces gas costs.
            pathLength += 1;

            if (currentKeyIndex == 0) {
                // First proof element is always the root node.
                require(keccak256(currentNode.encoded) == currentNodeID, "Invalid root hash");
            } else if (currentNode.encoded.length >= 32) {
                // Nodes 32 bytes or larger are hashed inside branch nodes.
                require(keccak256(currentNode.encoded) == currentNodeID, "Invalid large internal hash");
            } else {
                // Nodes smaller than 31 bytes aren't hashed.
                require(LibBytes.toBytes32(currentNode.encoded) == currentNodeID, "Invalid internal node hash");
            }

            if (currentNode.decoded.length == BRANCH_NODE_LENGTH) {
                if (currentKeyIndex == key.length) {
                    // We've hit the end of the key
                    // meaning the value should be within this branch node.
                    break;
                } else {
                    // We're not at the end of the key yet.
                    // Figure out what the next node ID should be and continue.
                    uint8 branchKey = uint8(key[currentKeyIndex]);
                    RLPItem nextNode = currentNode.decoded[branchKey];
                    (currentNodeID, currentNodeLength) = _getNodeID(nextNode);
                    currentKeyIncrement = 1;
                    continue;
                }
            } else if (currentNode.decoded.length == LEAF_OR_EXTENSION_NODE_LENGTH) {
                bytes memory path = _getNodePath(currentNode);
                uint8 prefix = uint8(path[0]);
                uint8 offset = 2 - prefix % 2;
                bytes memory pathRemainder = LibBytes.slice(path, offset);
                bytes memory keyRemainder = LibBytes.slice(key, currentKeyIndex);
                uint256 sharedNibbleLength = _getSharedNibbleLength(pathRemainder, keyRemainder);

                if (prefix == PREFIX_LEAF_EVEN || prefix == PREFIX_LEAF_ODD) {
                    if (pathRemainder.length == sharedNibbleLength && keyRemainder.length == sharedNibbleLength) {
                        // The key within this leaf matches our key exactly.
                        // Increment the key index to reflect that we have no remainder.
                        currentKeyIndex += sharedNibbleLength;
                    }

                    // We've hit a leaf node, so our next node should be NULL.
                    currentNodeID = bytes32(RLP_NULL);
                    break;
                } else if (prefix == PREFIX_EXTENSION_EVEN || prefix == PREFIX_EXTENSION_ODD) {
                    if (sharedNibbleLength != pathRemainder.length) {
                        // Our extension node is not identical to the remainder.
                        // We've hit the end of this path
                        // updates will need to modify this extension.
                        currentNodeID = bytes32(RLP_NULL);
                        break;
                    } else {
                        // Our extension shares some nibbles.
                        // Carry on to the next node.
                        (currentNodeID, currentNodeLength) = _getNodeID(currentNode.decoded[1]);
                        currentKeyIncrement = sharedNibbleLength;
                        continue;
                    }
                } else {
                    revert("Received a node with an unknown prefix");
                }
            } else {
                revert("Received an unparseable node.");
            }
        }

        // If our node ID is NULL, then we're at a dead end.
        bool isFinalNode = currentNodeID == bytes32(RLP_NULL);
        return (_proof, pathLength, LibBytes.slice(key, currentKeyIndex), isFinalNode);
    }

    /**
     * @notice Gets the path for a node.
     * @param _node Node to get a value for.
     * @return _value Node value, as hex bytes.
     */
    function _getNodeValue(TrieNode memory _node) private pure returns (bytes memory _value) {
        RLPItem _in = _node.decoded[_node.decoded.length - 1];
        // this is bytes only if the length is 32
        (uint256 itemOffset, uint256 itemLength, RLPItemType itemType) = RLPReaderLib._decodeLength(_in);

        if (itemType == RLPItemType.DATA_ITEM) {
            return RLPReaderLib._copy(_in.ptr(), itemOffset, itemLength);
        } else if (itemType == RLPItemType.LIST_ITEM) {
            require(_in.length() < 32, "bad _getNodeValue list");
            return RLPReaderLib._copy(_in.ptr(), 0, _in.length());
        }
        revert("bad _getNodeValue");
    }

    function GetTrie() internal pure returns (mapping(bytes32 => bytes) storage trie) {
        bytes32 position = keccak256("trie.trie.trie.trie");
        assembly {
            trie.slot := position
        }
    }

    function getTrieNode(bytes32 nodeId) private view returns (TrieNode memory) {
        bytes memory encoded = GetTrie()[nodeId];
        if (encoded.length == 0) {
            revert("bad hash in trie lookup");
        }
        require(keccak256(encoded) == nodeId, "bad hash in trie lookup");
        return getRawNode(encoded);
    }

    function getRawNode(bytes memory encoded) private pure returns (TrieNode memory) {
        return TrieNode({ encoded: encoded, decoded: RLPReaderLib.readList(encoded) });
    }
}
