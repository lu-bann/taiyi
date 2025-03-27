// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ISocketRegistry } from "../interfaces/ISocketRegistry.sol";

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { SocketRegistryStorage } from "../storage/SocketRegistryStorage.sol";

/**
 * @title A `Registry` that keeps track of operator sockets (arbitrary strings).
 * @author Layr Labs, Inc.
 */
contract SocketRegistry is SocketRegistryStorage {
    /// @notice A modifier that only allows the SlashingRegistryCoordinator to call a function
    modifier onlyRegistryCoordinator() {
        require(msg.sender == registryCoordinator, OnlyRegistryCoordinator());
        _;
    }

    constructor(ITaiyiRegistryCoordinator _registryCoordinator)
        SocketRegistryStorage(address(_registryCoordinator))
    { }

    /// @inheritdoc ISocketRegistry
    function setOperatorSocket(
        bytes32 _operatorId,
        string memory _socket
    )
        external
        onlyRegistryCoordinator
    {
        operatorIdToSocket[_operatorId] = _socket;
    }

    /// @inheritdoc ISocketRegistry
    function getOperatorSocket(bytes32 _operatorId)
        external
        view
        returns (string memory)
    {
        return operatorIdToSocket[_operatorId];
    }
}
