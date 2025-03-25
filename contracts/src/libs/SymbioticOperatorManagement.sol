// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { Subnetwork } from "@symbiotic/contracts/libraries/Subnetwork.sol";

library SymbioticOperatorManagement {
    using EnumerableSet for EnumerableSet.AddressSet;
    using Subnetwork for address;
    using Subnetwork for bytes32;

    struct SymbioticOperatorState {
        // Operator data by operator address
        mapping(address => IProposerRegistry.Operator) underwriterOperators;
        mapping(address => IProposerRegistry.Operator) validatorOperators;
        // Active operators by subnetwork
        mapping(bytes32 => EnumerableSet.AddressSet) subnetworkToOperators;
    }

    error OperatorNotRegistered(string message);
    error OperatorAlreadyRegistered(string message);

    function registerUnderwriterOperator(
        SymbioticOperatorState storage self,
        address operatorAddress,
        bytes calldata blsKey,
        address middlewareAddress
    )
        internal
    {
        // Underwriter subnetwork has identifier 1
        bytes32 subnetwork = middlewareAddress.subnetwork(1);

        require(
            !isRegistered(
                self,
                operatorAddress,
                IProposerRegistry.RestakingServiceType.SYMBIOTIC_UNDERWRITER
            ),
            "Already registered"
        );

        // Store operator data
        self.underwriterOperators[operatorAddress] = IProposerRegistry.Operator({
            operatorAddress: operatorAddress,
            restakingMiddlewareContract: middlewareAddress,
            serviceType: IProposerRegistry.RestakingServiceType.SYMBIOTIC_UNDERWRITER,
            blsKey: blsKey
        });

        // Add operator to subnetwork set
        self.subnetworkToOperators[subnetwork].add(operatorAddress);
    }

    function registerValidatorOperator(
        SymbioticOperatorState storage self,
        address operatorAddress,
        address middlewareAddress
    )
        internal
    {
        // Validator subnetwork has identifier 2
        bytes32 subnetwork = middlewareAddress.subnetwork(2);

        require(
            !isRegistered(
                self,
                operatorAddress,
                IProposerRegistry.RestakingServiceType.SYMBIOTIC_VALIDATOR
            ),
            "Already registered"
        );

        // Store operator data
        self.validatorOperators[operatorAddress] = IProposerRegistry.Operator({
            operatorAddress: operatorAddress,
            restakingMiddlewareContract: middlewareAddress,
            serviceType: IProposerRegistry.RestakingServiceType.SYMBIOTIC_VALIDATOR,
            blsKey: ""
        });

        // Add operator to subnetwork set
        self.subnetworkToOperators[subnetwork].add(operatorAddress);
    }

    function deregisterOperator(
        SymbioticOperatorState storage self,
        address operatorAddress,
        IProposerRegistry.RestakingServiceType serviceType,
        address middlewareAddress
    )
        internal
    {
        require(isRegistered(self, operatorAddress, serviceType), "Not registered");

        // Determine subnetwork based on service type
        uint96 subnetworkId = serviceType
            == IProposerRegistry.RestakingServiceType.SYMBIOTIC_UNDERWRITER ? 1 : 2;
        bytes32 subnetwork = middlewareAddress.subnetwork(subnetworkId);

        // Remove from subnetwork set
        self.subnetworkToOperators[subnetwork].remove(operatorAddress);

        // Clear operator data
        if (serviceType == IProposerRegistry.RestakingServiceType.SYMBIOTIC_UNDERWRITER) {
            delete self.underwriterOperators[operatorAddress];
        } else {
            delete self.validatorOperators[operatorAddress];
        }
    }

    function isRegistered(
        SymbioticOperatorState storage self,
        address operatorAddress,
        IProposerRegistry.RestakingServiceType serviceType
    )
        internal
        view
        returns (bool)
    {
        if (serviceType == IProposerRegistry.RestakingServiceType.SYMBIOTIC_UNDERWRITER) {
            return self.underwriterOperators[operatorAddress].operatorAddress
                == operatorAddress;
        } else {
            return self.validatorOperators[operatorAddress].operatorAddress
                == operatorAddress;
        }
    }

    function getOperatorData(
        SymbioticOperatorState storage self,
        address operatorAddress
    )
        internal
        view
        returns (
            IProposerRegistry.Operator memory underwriterOp,
            IProposerRegistry.Operator memory validatorOp
        )
    {
        underwriterOp = self.underwriterOperators[operatorAddress];
        validatorOp = self.validatorOperators[operatorAddress];
    }

    function getActiveOperators(
        SymbioticOperatorState storage self,
        bytes32 subnetwork
    )
        internal
        view
        returns (address[] memory)
    {
        return self.subnetworkToOperators[subnetwork].values();
    }

    function updateOperatorBLSKey(
        SymbioticOperatorState storage self,
        address operatorAddress,
        bytes calldata newBlsKey,
        address middlewareAddress
    )
        internal
    {
        if (
            !isRegistered(
                self,
                operatorAddress,
                IProposerRegistry.RestakingServiceType.SYMBIOTIC_UNDERWRITER
            )
        ) {
            revert OperatorNotRegistered("Not registered as underwriter operator");
        }

        self.underwriterOperators[operatorAddress].blsKey = newBlsKey;
    }
}
