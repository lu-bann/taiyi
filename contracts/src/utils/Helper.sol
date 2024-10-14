// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "open-zeppelin/utils/cryptography/ECDSA.sol";
import "../interfaces/Types.sol";
import "../libs/PreconfRequestLib.sol";

library Helper {
    using PreconfRequestLib for PreconfTx;

    function hashSignature(bytes memory signature) internal pure returns (bytes32) {
        return keccak256(signature);
    }

    function verifySignature(bytes32 hashValue, address signer, bytes memory signature) internal pure {
        address hash_signer = ECDSA.recover(hashValue, signature);
        require(hash_signer == signer, "Invalid signature");
    }
}
