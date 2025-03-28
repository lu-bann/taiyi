// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocationManager } from
    "@eigenlayer-contracts/src/contracts/core/AllocationManager.sol";
import {
    Allocation,
    OperatorSet
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";

import { IAVSRegistrar } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSRegistrar.sol";
import {
    IAllocationManager,
    IAllocationManagerTypes
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IPauserRegistry } from
    "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";

import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";

import { IPubkeyRegistry } from "../interfaces/IPubkeyRegistry.sol";
import { ISocketRegistry } from "../interfaces/ISocketRegistry.sol";

import { BN254 } from "../libs/BN254.sol";
import { BitmapUtils } from "../libs/BitmapUtils.sol";

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { Initializable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import { EIP712Upgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/utils/cryptography/EIP712Upgradeable.sol";

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { TaiyiRegistryCoordinatorStorage } from
    "../storage/TaiyiRegistryCoordinatorStorage.sol";
import { Pausable } from "@eigenlayer-contracts/src/contracts/permissions/Pausable.sol";

/// @title A `TaiyiRegistryCoordinator` that has two registries:
///      1) a `PubkeyRegistry` that keeps track of operators' public keys
///      2) a `SocketRegistry` that keeps track of operators' sockets (arbitrary strings)
contract TaiyiRegistryCoordinator is
    TaiyiRegistryCoordinatorStorage,
    Initializable,
    Pausable,
    OwnableUpgradeable,
    EIP712Upgradeable,
    IAVSRegistrar
{
    using BitmapUtils for *;
    using BN254 for BN254.G1Point;

    modifier onlyAllocationManager() {
        _checkAllocationManager();
        _;
    }

    modifier onlyEigenlayerMiddleware() {
        require(eigenlayerMiddleware == msg.sender, OnlyEigenlayerMiddleware());
        _;
    }

    constructor(
        IPubkeyRegistry _pubkeyRegistry,
        ISocketRegistry _socketRegistry,
        IAllocationManager _allocationManager,
        IPauserRegistry _pauserRegistry,
        string memory _version
    )
        TaiyiRegistryCoordinatorStorage(_pubkeyRegistry, _socketRegistry, _allocationManager)
        Pausable(_pauserRegistry)
    {
        _disableInitializers();
    }

    /// @notice External Functions Section
    function initialize(
        address initialOwner,
        uint256 initialPausedStatus,
        address _eigenlayerMiddleware
    )
        external
        initializer
    {
        __EIP712_init("AVSRegistryCoordinator", "v0.0.1");
        _transferOwnership(initialOwner);
        _setPausedStatus(initialPausedStatus);
    }

    /// @inheritdoc IAVSRegistrar
    function registerOperator(
        address operator,
        uint32[] memory operatorSetIds,
        bytes calldata data
    )
        external
        override
        onlyAllocationManager
        onlyWhenNotPaused(PAUSED_REGISTER_OPERATOR)
    {
        _registerOperator(operator, operatorSetIds, data);
    }

    /// @inheritdoc IAVSRegistrar
    function deregisterOperator(
        address operator,
        uint32[] memory operatorSetIds
    )
        external
        override
        onlyAllocationManager
        onlyWhenNotPaused(PAUSED_DEREGISTER_OPERATOR)
    {
        _deregisterOperator(operator, operatorSetIds);
    }

    /// @inheritdoc ITaiyiRegistryCoordinator
    function updateSocket(string memory socket) external {
        require(
            _operatorInfo[msg.sender].status == OperatorStatus.REGISTERED, NotRegistered()
        );
        _setOperatorSocket(_operatorInfo[msg.sender].operatorId, socket);
    }

    /// @inheritdoc ITaiyiRegistryCoordinator
    function setEigenlayerMiddleware(address _eigenlayerMiddleware) external onlyOwner {
        eigenlayerMiddleware = _eigenlayerMiddleware;
        _setRestakingServiceType(_eigenlayerMiddleware, RestakingServiceType.EIGENLAYER);
    }

    function _setRestakingServiceType(
        address _restakingMiddleware,
        RestakingServiceType _restakingServiceType
    )
        internal
    {
        restakingServiceType[_restakingMiddleware] = _restakingServiceType;
    }

    function _registerOperator(
        address operator,
        uint32[] memory operatorSetIds,
        bytes calldata data
    )
        internal
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(
            operatorInfo.status != OperatorStatus.REGISTERED, OperatorAlreadyRegistered()
        );

        (string memory socket, IPubkeyRegistry.PubkeyRegistrationParams memory params) =
            abi.decode(data, (string, IPubkeyRegistry.PubkeyRegistrationParams));

        /// If the operator has NEVER registered a pubkey before, use `params` to register
        /// their pubkey in pubkeyRegistry
        ///
        /// If the operator HAS registered a pubkey, `params` is ignored and the pubkey hash
        /// (operatorId) is fetched instead
        bytes32 operatorId = _getOrCreateOperatorId(operator, params);
        _setOperatorSocket(operatorId, socket);

        _operatorInfo[operator].status = OperatorStatus.REGISTERED;
        _operatorSets[operatorSetCounter].add(operator);
    }

    function _deregisterOperator(
        address operator,
        uint32[] memory operatorSetIds
    )
        internal
        virtual
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(operatorInfo.status == OperatorStatus.REGISTERED, OperatorNotRegistered());

        _deregisterOperatorFromOperatorSets(operator, operatorSetIds);
        operatorInfo.status = OperatorStatus.DEREGISTERED;
        _operatorSets[operatorSetCounter].remove(operator);
    }

    function createOperatorSet(IStrategy[] memory strategies)
        external
        onlyEigenlayerMiddleware
        returns (uint32)
    {
        IAllocationManagerTypes.CreateSetParams[] memory createSetParams =
            new IAllocationManagerTypes.CreateSetParams[](1);

        createSetParams[0] = IAllocationManagerTypes.CreateSetParams({
            operatorSetId: operatorSetCounter,
            strategies: strategies
        });
        allocationManager.createOperatorSets({
            avs: eigenlayerMiddleware,
            params: createSetParams
        });
        operatorSetCounter++;
    }

    function getOperatorSetOperators(uint32 operatorSetId)
        external
        view
        returns (address[] memory)
    {
        return _operatorSets[operatorSetId].values();
    }

    function getOperatorSetCount() external view returns (uint32) {
        return allocationManager.getOperatorSetCount(eigenlayerMiddleware);
    }

    function getOperatorSetStrategies(uint32 operatorSetId)
        external
        view
        returns (IStrategy[] memory)
    {
        OperatorSet memory operatorSet =
            allocationManager.getOperatorSet(eigenlayerMiddleware, operatorSetId);
        return allocationManager.getStrategiesInOperatorSet(operatorSet);
    }

    function addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyEigenlayerMiddleware
    {
        uint32 operatorSetCount =
            allocationManager.getOperatorSetCount(eigenlayerMiddleware);
        require(operatorSetId <= operatorSetCount, InvalidOperatorSetId());
        allocationManager.addStrategiesToOperatorSet({
            avs: eigenlayerMiddleware,
            operatorSetId: operatorSetId,
            strategies: strategies
        });
    }

    function removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyEigenlayerMiddleware
    {
        uint32 operatorSetCount =
            allocationManager.getOperatorSetCount(eigenlayerMiddleware);
        require(operatorSetId <= operatorSetCount, InvalidOperatorSetId());
        allocationManager.removeStrategiesFromOperatorSet({
            avs: eigenlayerMiddleware,
            operatorSetId: operatorSetId,
            strategies: strategies
        });
    }

    function _deregisterOperatorFromOperatorSets(
        address operator,
        uint32[] memory operatorSetIds
    )
        internal
        virtual
    {
        allocationManager.deregisterFromOperatorSets(
            IAllocationManagerTypes.DeregisterParams({
                operator: operator,
                avs: eigenlayerMiddleware,
                operatorSetIds: operatorSetIds
            })
        );
    }

    function _checkAllocationManager() internal view {
        require(msg.sender == address(allocationManager), OnlyAllocationManager());
    }

    /// @notice Fetches an operator's pubkey hash from the PubkeyRegistry. If the
    /// operator has not registered a pubkey, attempts to register a pubkey using
    /// `params`
    /// @param operator the operator whose pubkey to query from the PubkeyRegistry
    /// @param params contains the G1 & G2 public keys of the operator, and a signature proving their ownership
    /// @dev `params` can be empty if the operator has already registered a pubkey in the PubkeyRegistry
    function _getOrCreateOperatorId(
        address operator,
        IPubkeyRegistry.PubkeyRegistrationParams memory params
    )
        internal
        returns (bytes32 operatorId)
    {
        return pubkeyRegistry.getOrRegisterOperatorId(
            operator, params, pubkeyRegistrationMessageHash(operator)
        );
    }

    /// @notice Updates an operator's socket address in the SocketRegistry
    /// @param operatorId The unique identifier of the operator
    /// @param socket The new socket address to set for the operator
    /// @dev Emits an OperatorSocketUpdate event after updating
    function _setOperatorSocket(bytes32 operatorId, string memory socket) internal {
        socketRegistry.setOperatorSocket(operatorId, socket);
        emit OperatorSocketUpdate(operatorId, socket);
    }

    /// ========================================================================================
    /// ============== EIGENLAYER IN-PROTOCOL OPERATOR VIEW FUNCTIONS ==========================
    /// ========================================================================================

    /// @notice Returns all operator sets that an operator has allocated magnitude to
    /// @param operator The operator whose allocated sets to fetch
    /// @return Array of operator sets that the operator has allocated magnitude to
    function getOperatorAllocatedOperatorSets(address operator)
        external
        view
        returns (OperatorSet[] memory)
    {
        return allocationManager.getAllocatedSets(operator);
    }

    /// @notice Returns all strategies that an operator has allocated magnitude to in a specific operator set
    /// @param operator The operator whose allocated strategies to fetch
    /// @param operatorSetId The ID of the operator set to query
    /// @return Array of strategies that the operator has allocated magnitude to in the operator set
    function getOperatorAllocatedStrategies(
        address operator,
        uint32 operatorSetId
    )
        external
        view
        returns (IStrategy[] memory)
    {
        OperatorSet memory operatorSet =
            OperatorSet({ avs: eigenlayerMiddleware, operatorSetId: operatorSetId });
        return allocationManager.getAllocatedStrategies(operator, operatorSet);
    }

    /// @notice Returns an operator's allocation info for a specific strategy in an operator set
    /// @param operator The operator whose allocation to fetch
    /// @param operatorSetId The ID of the operator set to query
    /// @param strategy The strategy to query
    /// @return The operator's allocation info for the strategy in the operator set
    function getOperatorAllocatedStrategiesAmount(
        address operator,
        uint32 operatorSetId,
        IStrategy strategy
    )
        external
        view
        returns (Allocation memory)
    {
        OperatorSet memory operatorSet =
            OperatorSet({ avs: eigenlayerMiddleware, operatorSetId: operatorSetId });
        return allocationManager.getAllocation(operator, operatorSet, strategy);
    }

    /// @notice Returns all operator sets and allocations for a specific strategy that an operator has allocated magnitude to
    /// @param operator The operator whose allocations to fetch
    /// @param strategy The strategy to query
    /// @return Array of operator sets and corresponding allocations for the strategy
    function getOperatorStrategyAllocations(
        address operator,
        IStrategy strategy
    )
        external
        view
        returns (OperatorSet[] memory, Allocation[] memory)
    {
        return allocationManager.getStrategyAllocations(operator, strategy);
    }

    /// ========================================================================================
    /// ============== EIGENLAYER OUT-PROTOCOL OPERATOR VIEW FUNCTIONS =========================
    /// ========================================================================================

    function getOperator(address operator) external view returns (OperatorInfo memory) {
        return _operatorInfo[operator];
    }

    /// @notice Returns the operatorId for the given `operator`
    function getOperatorId(address operator) external view returns (bytes32) {
        return _operatorInfo[operator].operatorId;
    }

    /// @notice Returns the operator address for the given `operatorId`
    function getOperatorFromId(bytes32 operatorId) external view returns (address) {
        return pubkeyRegistry.getOperatorFromId(operatorId);
    }

    /// @notice Returns the status for the given `operator`
    function getOperatorStatus(address operator)
        external
        view
        returns (ITaiyiRegistryCoordinator.OperatorStatus)
    {
        return _operatorInfo[operator].status;
    }

    /// @notice Returns the message hash that an operator must sign to register their BLS public key.
    /// @param operator is the address of the operator registering their BLS public key
    function pubkeyRegistrationMessageHash(address operator)
        public
        view
        returns (BN254.G1Point memory)
    {
        return BN254.hashToG1(calculatePubkeyRegistrationMessageHash(operator));
    }

    /// @notice Returns the message hash that an operator must sign to register their BLS public key.
    /// @param operator is the address of the operator registering their BLS public key
    function calculatePubkeyRegistrationMessageHash(address operator)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(PUBKEY_REGISTRATION_TYPEHASH, operator))
        );
    }
}
