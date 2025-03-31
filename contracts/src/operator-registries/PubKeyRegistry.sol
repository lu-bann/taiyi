// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IPubkeyRegistry } from "../interfaces/IPubkeyRegistry.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { BN254 } from "../libs/BN254.sol";
import { PubkeyRegistryStorage } from "../storage/PubkeyRegistryStorage.sol";
import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { console } from "forge-std/console.sol";

contract PubkeyRegistry is PubkeyRegistryStorage, IPubkeyRegistry {
    using BN254 for BN254.G1Point;

    /// @notice when applied to a function, only allows the RegistryCoordinator to call it
    modifier onlyRegistryCoordinator() {
        _checkRegistryCoordinator();
        _;
    }

    /// @notice when applied to a function, only allows the RegistryCoordinator owner to call it
    modifier onlyRegistryCoordinatorOwner() {
        _checkRegistryCoordinatorOwner();
        _;
    }

    /// @notice Sets the (immutable) `registryCoordinator` address
    constructor(ITaiyiRegistryCoordinator _registryCoordinator)
        PubkeyRegistryStorage(_registryCoordinator)
    { }

    // Todo: remove bypass in test mode
    /// @inheritdoc IPubkeyRegistry
    function registerBLSPublicKey(
        address operator,
        PubkeyRegistrationParams calldata params,
        BN254.G1Point calldata pubkeyRegistrationMessageHash
    )
        public
        onlyRegistryCoordinator
        returns (bytes32 operatorId)
    {
        bytes32 pubkeyHash = BN254.hashG1Point(params.pubkeyG1);
        require(pubkeyHash != ZERO_PK_HASH, ZeroPubKey());
        require(getOperatorId(operator) == bytes32(0), OperatorAlreadyRegistered());
        require(
            pubkeyHashToOperator[pubkeyHash] == address(0), BLSPubkeyAlreadyRegistered()
        );

        // In test mode (Anvil/Hardhat chain ID), we'll skip the signature verification
        if (block.chainid != 31_337) {
            // gamma = h(sigma, P, P', H(m))
            uint256 gamma = uint256(
                keccak256(
                    abi.encodePacked(
                        params.pubkeyRegistrationSignature.X,
                        params.pubkeyRegistrationSignature.Y,
                        params.pubkeyG1.X,
                        params.pubkeyG1.Y,
                        params.pubkeyG2.X,
                        params.pubkeyG2.Y,
                        pubkeyRegistrationMessageHash.X,
                        pubkeyRegistrationMessageHash.Y
                    )
                )
            ) % BN254.FR_MODULUS;

            // e(sigma + P * gamma, [-1]_2) = e(H(m) + [1]_1 * gamma, P')
            require(
                BN254.pairing(
                    params.pubkeyRegistrationSignature.plus(
                        params.pubkeyG1.scalar_mul(gamma)
                    ),
                    BN254.negGeneratorG2(),
                    pubkeyRegistrationMessageHash.plus(
                        BN254.generatorG1().scalar_mul(gamma)
                    ),
                    params.pubkeyG2
                ),
                InvalidBLSSignatureOrPrivateKey()
            );
        } else {
            // We're in test mode, log this bypass
            console.log(
                "Bypassing BLS signature validation in test mode for operator:", operator
            );
        }

        operatorToPubkey[operator] = params.pubkeyG1;
        operatorToPubkeyG2[operator] = params.pubkeyG2;
        operatorToPubkeyHash[operator] = pubkeyHash;
        pubkeyHashToOperator[pubkeyHash] = operator;

        emit NewPubkeyRegistration(operator, params.pubkeyG1, params.pubkeyG2);
        return pubkeyHash;
    }

    function getOrRegisterOperatorId(
        address operator,
        PubkeyRegistrationParams calldata params,
        BN254.G1Point calldata pubkeyRegistrationMessageHash
    )
        external
        onlyRegistryCoordinator
        returns (bytes32 operatorId)
    {
        operatorId = getOperatorId(operator);
        if (operatorId == 0) {
            operatorId =
                registerBLSPublicKey(operator, params, pubkeyRegistrationMessageHash);
        }
        return operatorId;
    }

    /// @notice Verifies and registers a G2 public key for an operator that already has a G1 key
    /// @dev This is meant to be used as a one-time way to add G2 public keys for operators that have G1 keys but no G2 key on chain
    /// @param operator The address of the operator to register the G2 key for
    /// @param pubkeyG2 The G2 public key to register
    function verifyAndRegisterG2PubkeyForOperator(
        address operator,
        BN254.G2Point calldata pubkeyG2
    )
        external
        onlyRegistryCoordinatorOwner
    {
        // Get the operator's G1 pubkey. Reverts if they have not registered a key
        (BN254.G1Point memory pubkeyG1,) = getRegisteredPubkey(operator);

        _checkG2PubkeyNotSet(operator);

        require(
            BN254.pairing(pubkeyG1, BN254.negGeneratorG2(), BN254.generatorG1(), pubkeyG2),
            InvalidBLSSignatureOrPrivateKey()
        );

        operatorToPubkeyG2[operator] = pubkeyG2;

        emit NewG2PubkeyRegistration(operator, pubkeyG2);
    }

    /// @inheritdoc IPubkeyRegistry
    function getRegisteredPubkey(address operator)
        public
        view
        returns (BN254.G1Point memory, bytes32)
    {
        BN254.G1Point memory pubkey = operatorToPubkey[operator];
        bytes32 pubkeyHash = getOperatorId(operator);

        require(pubkeyHash != bytes32(0), OperatorNotRegistered());

        return (pubkey, pubkeyHash);
    }

    /// @inheritdoc IPubkeyRegistry
    function getOperatorFromId(bytes32 operatorId) public view returns (address) {
        return pubkeyHashToOperator[operatorId];
    }

    /// @inheritdoc IPubkeyRegistry
    function getOperatorId(address operator) public view returns (bytes32) {
        return operatorToPubkeyHash[operator];
    }

    /// @inheritdoc IPubkeyRegistry
    function getOperatorPubkeyG2(address operator)
        public
        view
        override
        returns (BN254.G2Point memory)
    {
        return operatorToPubkeyG2[operator];
    }

    function _checkRegistryCoordinator() internal view {
        require(msg.sender == address(registryCoordinator), OnlyRegistryCoordinator());
    }

    function _checkRegistryCoordinatorOwner() internal view {
        require(
            msg.sender == OwnableUpgradeable(address(registryCoordinator)).owner(),
            OnlyRegistryCoordinatorOwner()
        );
    }

    /// @notice Checks if a G2 pubkey is already set for an operator
    function _checkG2PubkeyNotSet(address operator) internal view {
        BN254.G2Point memory existingG2Pubkey = getOperatorPubkeyG2(operator);
        require(
            existingG2Pubkey.X[0] == 0 && existingG2Pubkey.X[1] == 0
                && existingG2Pubkey.Y[0] == 0 && existingG2Pubkey.Y[1] == 0,
            G2PubkeyAlreadySet()
        );
    }
}
