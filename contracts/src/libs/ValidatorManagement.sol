// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";

library ValidatorManagement {
    using ValidatorManagement for ValidatorState;

    struct ValidatorState {
        mapping(bytes32 => IProposerRegistry.Validator) validators;
        mapping(address => bytes[]) operatorToPubkeys;
    }

    /// @notice Event emitted when a validator's delegatee is updated
    event ValidatorDelegateeUpdated(
        bytes32 indexed pubKeyHash, bytes oldDelegatee, bytes newDelegatee
    );

    function registerValidator(
        ValidatorState storage self,
        bytes calldata pubkey,
        address operator,
        bytes calldata delegatee
    )
        internal
        returns (bytes32)
    {
        require(delegatee.length > 0, "Invalid delegatee");

        bytes32 pubkeyHash = keccak256(pubkey);
        require(
            self.validators[pubkeyHash].status
                == IProposerRegistry.ValidatorStatus.NotRegistered,
            "Validator already registered"
        );

        // Store validator data
        self.validators[pubkeyHash] = IProposerRegistry.Validator({
            pubkey: pubkey,
            status: IProposerRegistry.ValidatorStatus.Active,
            optOutTimestamp: 0,
            operator: operator,
            delegatee: delegatee
        });

        // Add pubkey to operator's list
        self.operatorToPubkeys[operator].push(pubkey);

        return pubkeyHash;
    }

    function clearOperatorForValidator(
        ValidatorState storage self,
        address operator
    )
        internal
    {
        delete self.operatorToPubkeys[operator];
    }

    function initOptOut(
        ValidatorState storage self,
        bytes32 pubKeyHash,
        uint256 signatureExpiry
    )
        internal
    {
        require(
            self.validators[pubKeyHash].status == IProposerRegistry.ValidatorStatus.Active,
            "Validator not active"
        );
        require(signatureExpiry > block.timestamp, "Signature expired");

        self.validators[pubKeyHash].status = IProposerRegistry.ValidatorStatus.OptingOut;
        self.validators[pubKeyHash].optOutTimestamp = block.timestamp;
    }

    function confirmOptOut(ValidatorState storage self, bytes32 pubKeyHash) internal {
        require(
            self.validators[pubKeyHash].status
                == IProposerRegistry.ValidatorStatus.OptingOut,
            "Validator not opting out"
        );

        self.validators[pubKeyHash].status = IProposerRegistry.ValidatorStatus.OptedOut;
    }

    function getValidatorStatus(
        ValidatorState storage self,
        bytes32 pubKeyHash
    )
        internal
        view
        returns (IProposerRegistry.ValidatorStatus)
    {
        return self.validators[pubKeyHash].status;
    }

    function getValidator(
        ValidatorState storage self,
        bytes32 pubKeyHash
    )
        internal
        view
        returns (IProposerRegistry.Validator memory)
    {
        return self.validators[pubKeyHash];
    }

    function getOperatorValidators(
        ValidatorState storage self,
        address operator
    )
        internal
        view
        returns (bytes[] memory)
    {
        return self.operatorToPubkeys[operator];
    }

    function updateValidatorDelegatee(
        ValidatorState storage self,
        bytes32 pubKeyHash,
        bytes calldata newDelegatee
    )
        internal
    {
        require(
            self.validators[pubKeyHash].status
                != IProposerRegistry.ValidatorStatus.NotRegistered,
            "Validator not registered"
        );

        bytes memory oldDelegatee = self.validators[pubKeyHash].delegatee;
        self.validators[pubKeyHash].delegatee = newDelegatee;

        emit ValidatorDelegateeUpdated(pubKeyHash, oldDelegatee, newDelegatee);
    }
}
