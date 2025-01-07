// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../libs/PreconfRequestLib.sol";
import "../types/PreconfRequestBTypes.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

library Helper {
    using PreconfRequestLib for PreconfRequestBType;

    function hashSignature(bytes memory signature) internal pure returns (bytes32) {
        return keccak256(signature);
    }

    function verifySignature(
        bytes32 hashValue,
        address signer,
        bytes memory signature,
        string memory errorMessage
    )
        internal
        pure
    {
        address hash_signer = ECDSA.recover(hashValue, signature);
        require(hash_signer == signer, errorMessage);
    }

    function verifySignature(
        bytes memory hashValue,
        address signer,
        bytes memory signature,
        string memory errorMessage
    )
        internal
        pure
    {
        bytes32 hashValue32 = keccak256(hashValue);
        address hash_signer = ECDSA.recover(hashValue32, signature);
        require(hash_signer == signer, errorMessage);
    }
}
