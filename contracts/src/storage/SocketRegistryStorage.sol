// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ISocketRegistry } from "../interfaces/ISocketRegistry.sol";

abstract contract SocketRegistryStorage is ISocketRegistry {
    /**
     *
     *                            CONSTANTS AND IMMUTABLES
     *
     */

    /// @notice The address of the RegistryCoordinator
    address public immutable registryCoordinator;

    /**
     *
     *                                    STATE
     *
     */

    /// @notice A mapping from operator IDs to their sockets
    mapping(bytes32 => string) public operatorIdToSocket;

    constructor(address _registryCoordinator) {
        registryCoordinator = _registryCoordinator;
    }

    uint256[50] private __GAP;
}
