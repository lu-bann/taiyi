// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

library EigenLayerOperatorManagement {
    using EnumerableSet for EnumerableSet.AddressSet;

    struct EigenLayerOperatorState {
        mapping(address => IProposerRegistry.Operator) underwriterOperators;
        mapping(address => IProposerRegistry.Operator) validatorOperators;
        mapping(address => EnumerableSet.AddressSet) avsToOperators;
    }

    error OperatorNotRegistered(string message);

    function registerUnderwriterOperator(
        EigenLayerOperatorState storage self,
        address operatorAddress,
        bytes calldata blsKey,
        address avsAddress
    )
        internal
    {
        require(
            !isRegistered(
                self,
                operatorAddress,
                IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER
            ),
            "Already registered"
        );

        // Store operator data
        self.underwriterOperators[operatorAddress] = IProposerRegistry.Operator({
            operatorAddress: operatorAddress,
            restakingMiddlewareContract: avsAddress,
            serviceType: IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER,
            blsKey: blsKey
        });

        // Add operator to AVS set
        self.avsToOperators[avsAddress].add(operatorAddress);
    }

    function registerValidatorOperator(
        EigenLayerOperatorState storage self,
        address operatorAddress,
        address avsAddress
    )
        internal
    {
        require(
            !isRegistered(
                self,
                operatorAddress,
                IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR
            ),
            "Already registered"
        );

        // Store operator data
        self.validatorOperators[operatorAddress] = IProposerRegistry.Operator({
            operatorAddress: operatorAddress,
            restakingMiddlewareContract: avsAddress,
            serviceType: IProposerRegistry.RestakingServiceType.EIGENLAYER_VALIDATOR,
            blsKey: ""
        });

        // Add operator to AVS set
        self.avsToOperators[avsAddress].add(operatorAddress);
    }

    function deregisterOperator(
        EigenLayerOperatorState storage self,
        address operatorAddress,
        IProposerRegistry.RestakingServiceType serviceType,
        address avsAddress
    )
        internal
    {
        require(isRegistered(self, operatorAddress, serviceType), "Not registered");

        // Remove from AVS set
        self.avsToOperators[avsAddress].remove(operatorAddress);

        // Clear operator data
        if (serviceType == IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER)
        {
            delete self.underwriterOperators[operatorAddress];
        } else {
            delete self.validatorOperators[operatorAddress];
        }
    }

    function isRegistered(
        EigenLayerOperatorState storage self,
        address operatorAddress,
        IProposerRegistry.RestakingServiceType serviceType
    )
        internal
        view
        returns (bool)
    {
        if (serviceType == IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER)
        {
            return self.underwriterOperators[operatorAddress].operatorAddress
                == operatorAddress;
        } else {
            return self.validatorOperators[operatorAddress].operatorAddress
                == operatorAddress;
        }
    }

    function getOperatorData(
        EigenLayerOperatorState storage self,
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
        EigenLayerOperatorState storage self,
        address avsAddress
    )
        internal
        view
        returns (address[] memory)
    {
        return self.avsToOperators[avsAddress].values();
    }

    function updateOperatorBLSKey(
        EigenLayerOperatorState storage self,
        address operatorAddress,
        bytes calldata newBlsKey
    )
        internal
    {
        if (
            !isRegistered(
                self,
                operatorAddress,
                IProposerRegistry.RestakingServiceType.EIGENLAYER_UNDERWRITER
            )
        ) {
            revert OperatorNotRegistered(
                "Operator not registered as underwriter operator"
            );
        }

        self.underwriterOperators[operatorAddress].blsKey = newBlsKey;
    }
}
