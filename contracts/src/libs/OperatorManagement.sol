// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

library OperatorManagement {
    using EnumerableSet for EnumerableSet.AddressSet;

    struct OperatorState {
        mapping(address => uint8) registrationStatus;
        mapping(address => bytes) blsKeys;
        mapping(address => address) middlewareContracts;
        mapping(address => EnumerableSet.AddressSet) avsToOperators;
    }

    function registerGatewayOperator(
        OperatorState storage self,
        address operatorAddress,
        bytes calldata blsKey,
        address avsAddress
    )
        internal
    {
        require(
            !isRegistered(self, operatorAddress, IProposerRegistry.AVSType.GATEWAY),
            "Already registered"
        );

        // Set registration bit for Gateway AVS (bit 0)
        self.registrationStatus[operatorAddress] |= 1;

        self.blsKeys[operatorAddress] = blsKey;
        self.middlewareContracts[operatorAddress] = avsAddress;

        self.avsToOperators[avsAddress].add(operatorAddress);
    }

    function registerValidatorOperator(
        OperatorState storage self,
        address operatorAddress,
        address avsAddress
    )
        internal
    {
        require(
            !isRegistered(self, operatorAddress, IProposerRegistry.AVSType.VALIDATOR),
            "Already registered"
        );

        // Set registration bit for Validator AVS (bit 1)
        self.registrationStatus[operatorAddress] |= 2;

        self.middlewareContracts[operatorAddress] = avsAddress;

        self.avsToOperators[avsAddress].add(operatorAddress);
    }

    function deregisterOperator(
        OperatorState storage self,
        address operatorAddress,
        IProposerRegistry.AVSType avsType,
        address avsAddress
    )
        internal
    {
        require(isRegistered(self, operatorAddress, avsType), "Not registered");

        // Remove from AVS set
        self.avsToOperators[avsAddress].remove(operatorAddress);

        // Clear operator data
        if (avsType == IProposerRegistry.AVSType.GATEWAY) {
            // Clear Gateway bit (bit 0)
            self.registrationStatus[operatorAddress] &= 2;
            delete self.blsKeys[operatorAddress];
        } else {
            // Clear Validator bit (bit 1)
            self.registrationStatus[operatorAddress] &= 1;
        }

        if (self.registrationStatus[operatorAddress] == 0) {
            delete self.middlewareContracts[operatorAddress];
        }
    }

    function isRegistered(
        OperatorState storage self,
        address operatorAddress,
        IProposerRegistry.AVSType avsType
    )
        internal
        view
        returns (bool)
    {
        uint8 status = self.registrationStatus[operatorAddress];
        return avsType == IProposerRegistry.AVSType.GATEWAY
            ? (status & 1) != 0
            : (status & 2) != 0;
    }

    function getOperatorData(
        OperatorState storage self,
        address operatorAddress
    )
        internal
        view
        returns (
            IProposerRegistry.Operator memory gatewayOp,
            IProposerRegistry.Operator memory validatorOp
        )
    {
        uint8 status = self.registrationStatus[operatorAddress];

        if ((status & 1) != 0) {
            gatewayOp = IProposerRegistry.Operator({
                operatorAddress: operatorAddress,
                restakingMiddlewareContract: self.middlewareContracts[operatorAddress],
                avsType: IProposerRegistry.AVSType.GATEWAY,
                blsKey: self.blsKeys[operatorAddress]
            });
        }

        if ((status & 2) != 0) {
            validatorOp = IProposerRegistry.Operator({
                operatorAddress: operatorAddress,
                restakingMiddlewareContract: self.middlewareContracts[operatorAddress],
                avsType: IProposerRegistry.AVSType.VALIDATOR,
                blsKey: ""
            });
        }
    }

    function getActiveOperators(
        OperatorState storage self,
        address avsAddress
    )
        internal
        view
        returns (address[] memory)
    {
        return self.avsToOperators[avsAddress].values();
    }
}
