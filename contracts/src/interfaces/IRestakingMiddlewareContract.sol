// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IRestakingMiddlewareContract {
    // ========= INITIALIZER & UPGRADE FUNCTIONS =========

    /// @notice Initializes the middleware contract.
    /// @param _owner The address of the contract owner.
    /// @param _parameters The address of the parameters contract.
    /// @param _manager The address of the Bolt Manager contract.
    /// @param restakingProtocolAddresses Additional addresses specific to the
    /// restaking protocol.
    function initialize(
        address _owner,
        address _parameters,
        address _manager,
        address[] calldata restakingProtocolAddresses
    )
        external;

    /// @notice Upgrades the middleware contract to version 2.
    /// @param _owner The address of the contract owner.
    /// @param _parameters The address of the parameters contract.
    /// @param _manager The address of the Bolt Manager contract.
    /// @param restakingProtocolAddresses Additional addresses specific to the
    /// restaking protocol.
    function initializeV2(
        address _owner,
        address _parameters,
        address _manager,
        address[] calldata restakingProtocolAddresses
    )
        external;

    // ========= OPERATOR MANAGEMENT =========

    /// @notice Allows an operator to register with the middleware
    /// (EigenLayer-specific).
    /// @param rpc The RPC URL of the operator.
    function registerOperator(string calldata rpc) external;

    /// @notice Deregisters an operator from the middleware.
    function deregisterOperator() external;

    /// @notice Pauses an operator, signaling indefinite opt-out from the
    /// protocol.
    function pauseOperator() external;

    /// @notice Unpauses an operator, allowing them to opt back into the
    /// protocol.
    function unpauseOperator() external;

    /// @notice Checks if an operator is registered.
    /// @param operator The address of the operator.
    /// @return True if the operator is registered, false otherwise.
    function isOperatorRegistered(address operator) external view returns (bool);

    // ========= RESTAKING ENTITY MANAGEMENT =========

    /// @notice Registers a restaking entity (strategy or vault) to work with
    /// the middleware.
    /// @param entity The address of the restaking entity.
    function registerRestakingEntity(address entity) external;

    /// @notice Deregisters a restaking entity from the middleware.
    /// @param entity The address of the restaking entity.
    function deregisterRestakingEntity(address entity) external;

    /// @notice Pauses a restaking entity, signaling indefinite opt-out from the
    /// protocol.
    function pauseRestakingEntity() external;

    /// @notice Unpauses a restaking entity, allowing it to opt back into the
    /// protocol.
    function unpauseRestakingEntity() external;

    /// @notice Checks if a restaking entity is currently enabled.
    /// @param entity The address of the restaking entity.
    /// @return True if the entity is enabled, false otherwise.
    function isRestakingEntityEnabled(address entity) external view returns (bool);

    /// @notice Gets the list of whitelisted restaking entities.
    /// @return An array of addresses of whitelisted entities.
    function getWhitelistedRestakingEntities() external view returns (address[] memory);

    // ========= STAKE AND COLLATERAL MANAGEMENT =========

    /// @notice Gets the collaterals and amounts staked by an operator across
    /// supported entities.
    /// @param operator The address of the operator.
    /// @return collaterals An array of collateral token addresses.
    /// @return amounts An array of amounts staked corresponding to each
    /// collateral.
    function getOperatorCollaterals(address operator)
        external
        view
        returns (address[] memory collaterals, uint256[] memory amounts);

    /// @notice Gets the amount of tokens delegated to an operator for a
    /// specific collateral.
    /// @param operator The address of the operator.
    /// @param collateral The address of the collateral token.
    /// @return amount The amount of tokens delegated to the operator.
    function getOperatorStake(
        address operator,
        address collateral
    )
        external
        view
        returns (uint256 amount);

    /// @notice Gets the stake of an operator at a specific timestamp.
    /// @param operator The address of the operator.
    /// @param collateral The address of the collateral token.
    /// @param timestamp The timestamp to check the stake at.
    /// @return amount The stake of the operator at the given timestamp.
    function getOperatorStakeAt(
        address operator,
        address collateral,
        uint48 timestamp
    )
        external
        view
        returns (uint256 amount);

    // ========= EPOCH MANAGEMENT =========

    /// @notice Gets the start timestamp of a specific epoch.
    /// @param epoch The epoch number.
    /// @return timestamp The start timestamp of the epoch.
    function getEpochStartTs(uint48 epoch) external view returns (uint48 timestamp);

    /// @notice Gets the epoch number at a specific timestamp.
    /// @param timestamp The timestamp to get the epoch for.
    /// @return epoch The epoch number at the given timestamp.
    function getEpochAtTs(uint48 timestamp) external view returns (uint48 epoch);

    /// @notice Gets the current epoch number.
    /// @return epoch The current epoch number.
    function getCurrentEpoch() external view returns (uint48 epoch);

    // ========= PROTOCOL-SPECIFIC FUNCTIONS =========

    /// @notice Updates the metadata URI for the AVS (EigenLayer-specific).
    /// @param metadataURI The URI for metadata associated with the AVS.
    function updateAVSMetadataURI(string calldata metadataURI) external;

    /// @notice Registers an operator to the AVS (EigenLayer-specific).
    /// @param operator The address of the operator.
    function registerOperatorToAVS(address operator) external;

    /// @notice Deregisters an operator from the AVS (EigenLayer-specific).
    /// @param operator The address of the operator.
    function deregisterOperatorFromAVS(address operator) external;

    /// @notice Gets the restaked strategies for an operator
    /// (EigenLayer-specific).
    /// @param operator The address of the operator.
    /// @return An array of strategy addresses.
    function getOperatorRestakedStrategies(address operator)
        external
        view
        returns (address[] memory);

    /// @notice Gets the restakeable strategies (EigenLayer-specific).
    /// @return An array of strategy addresses.
    function getRestakeableStrategies() external view returns (address[] memory);

    /// @notice Gets the address of the AVS directory (EigenLayer-specific).
    /// @return The address of the AVS directory.
    function avsDirectory() external view returns (address);

    /// @notice Allows slashing of an operator's stake (Symbiotic-specific).
    /// @param timestamp The timestamp of the slash event.
    /// @param operator The address of the operator to slash.
    /// @param collateral The address of the collateral token.
    /// @param amount The amount to slash.
    function slash(
        uint48 timestamp,
        address operator,
        address collateral,
        uint256 amount
    )
        external;
}
