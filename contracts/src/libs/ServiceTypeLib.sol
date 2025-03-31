// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

/// @title ServiceTypeLib
/// @notice Library for converting between RestakingServiceTypes and uint32 identifiers
/// @dev Provides utility functions to map enum values to uint32 IDs and back
library ServiceTypeLib {
    /// @notice Convert a RestakingServiceTypes enum to its corresponding uint32 identifier
    /// @param serviceType The RestakingServiceTypes enum value
    /// @return The uint32 identifier representing the service type
    function toId(ITaiyiRegistryCoordinator.RestakingServiceTypes serviceType)
        internal
        pure
        returns (uint32)
    {
        if (
            serviceType
                == ITaiyiRegistryCoordinator.RestakingServiceTypes.EIGENLAYER_VALIDATOR
        ) {
            return 1;
        } else if (
            serviceType
                == ITaiyiRegistryCoordinator.RestakingServiceTypes.EIGENLAYER_UNDERWRITER
        ) {
            return 2;
        } else if (
            serviceType
                == ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_VALIDATOR
        ) {
            return 3;
        } else if (
            serviceType
                == ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_UNDERWRITER
        ) {
            return 4;
        } else {
            // Default case or unknown type
            revert("Unknown service type");
        }
    }

    /// @notice Convert a uint32 identifier back to its corresponding RestakingServiceTypes enum
    /// @param id The uint32 identifier
    /// @return The RestakingServiceTypes enum value
    function fromId(uint32 id)
        internal
        pure
        returns (ITaiyiRegistryCoordinator.RestakingServiceTypes)
    {
        if (id == 1) {
            return ITaiyiRegistryCoordinator.RestakingServiceTypes.EIGENLAYER_VALIDATOR;
        } else if (id == 2) {
            return ITaiyiRegistryCoordinator.RestakingServiceTypes.EIGENLAYER_UNDERWRITER;
        } else if (id == 3) {
            return ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_VALIDATOR;
        } else if (id == 4) {
            return ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_UNDERWRITER;
        } else {
            // Default case or invalid ID
            revert("Invalid service type ID");
        }
    }

    /// @notice Check if a service type is an EigenLayer type
    /// @param serviceType The RestakingServiceTypes enum value
    /// @return True if the service type is an EigenLayer type
    function isEigenLayerType(ITaiyiRegistryCoordinator.RestakingServiceTypes serviceType)
        internal
        pure
        returns (bool)
    {
        return serviceType
            == ITaiyiRegistryCoordinator.RestakingServiceTypes.EIGENLAYER_VALIDATOR
            || serviceType
                == ITaiyiRegistryCoordinator.RestakingServiceTypes.EIGENLAYER_UNDERWRITER;
    }

    /// @notice Check if a service type is a Symbiotic type
    /// @param serviceType The RestakingServiceTypes enum value
    /// @return True if the service type is a Symbiotic type
    function isSymbioticType(ITaiyiRegistryCoordinator.RestakingServiceTypes serviceType)
        internal
        pure
        returns (bool)
    {
        return serviceType
            == ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_VALIDATOR
            || serviceType
                == ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_UNDERWRITER;
    }

    /// @notice Check if a service type is a validator type
    /// @param serviceType The RestakingServiceTypes enum value
    /// @return True if the service type is a validator type
    function isValidatorType(ITaiyiRegistryCoordinator.RestakingServiceTypes serviceType)
        internal
        pure
        returns (bool)
    {
        return serviceType
            == ITaiyiRegistryCoordinator.RestakingServiceTypes.EIGENLAYER_VALIDATOR
            || serviceType
                == ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_VALIDATOR;
    }

    /// @notice Check if a service type is an underwriter type
    /// @param serviceType The RestakingServiceTypes enum value
    /// @return True if the service type is an underwriter type
    function isUnderwriterType(
        ITaiyiRegistryCoordinator.RestakingServiceTypes serviceType
    )
        internal
        pure
        returns (bool)
    {
        return serviceType
            == ITaiyiRegistryCoordinator.RestakingServiceTypes.EIGENLAYER_UNDERWRITER
            || serviceType
                == ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_UNDERWRITER;
    }

    /// @notice Get the operator set ID associated with a service type
    /// @param serviceType The RestakingServiceTypes enum value
    /// @return The operator set ID (0 for underwriter, 1 for validator)
    function getOperatorSetId(ITaiyiRegistryCoordinator.RestakingServiceTypes serviceType)
        internal
        pure
        returns (uint32)
    {
        if (isValidatorType(serviceType)) {
            return 1; // Validator set
        } else if (isUnderwriterType(serviceType)) {
            return 0; // Underwriter set
        } else {
            revert("Invalid service type");
        }
    }

    /// @notice Get an array containing the operator set ID associated with a service type
    /// @param serviceType The RestakingServiceTypes enum value
    /// @return Array containing the operator set ID
    function getOperatorSetIds(
        ITaiyiRegistryCoordinator.RestakingServiceTypes serviceType
    )
        internal
        pure
        returns (uint32[] memory)
    {
        uint32[] memory operatorSetIds = new uint32[](1);
        operatorSetIds[0] = getOperatorSetId(serviceType);
        return operatorSetIds;
    }
}
