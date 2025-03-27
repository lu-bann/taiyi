// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocationManager } from
    "@eigenlayer-contracts/src/contracts/core/AllocationManager.sol";
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
///
/// @author Layr Labs, Inc.
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
        address restakingMiddleware
    )
        external
        initializer
    {
        __EIP712_init("AVSRegistryCoordinator", "v0.0.1");
        _transferOwnership(initialOwner);
        _setPausedStatus(initialPausedStatus);
        _setRestakingMiddleware(restakingMiddleware);
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
        _kickOperator(operator, operatorSetIds);
    }

    /// @inheritdoc ITaiyiRegistryCoordinator
    function updateSocket(string memory socket) external {
        require(
            _operatorInfo[msg.sender].status == OperatorStatus.REGISTERED, NotRegistered()
        );
        _setOperatorSocket(_operatorInfo[msg.sender].operatorId, socket);
    }

    /// @inheritdoc ITaiyiRegistryCoordinator
    function setRestakingMiddleware(address _restakingMiddleware) external onlyOwner {
        _setRestakingMiddleware(_restakingMiddleware);
    }

    /// @notice Internal function to handle operator ejection logic
    /// @param operator The operator to force deregister from the avs
    /// @param operatorSetIds The operator sets to eject the operator from
    function _kickOperator(
        address operator,
        uint32[] memory operatorSetIds
    )
        internal
        virtual
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(operatorInfo.status == OperatorStatus.REGISTERED, OperatorNotRegistered());

        bytes32 operatorId = operatorInfo.operatorId;
        _forceDeregisterOperatorFromAllOperatorSets(operator, operatorSetIds);
        operatorInfo.status = OperatorStatus.DEREGISTERED;
    }

    function createOperatorSet(IStrategy[] memory strategies) external onlyOwner {
        operatorSetCount++;

        // Create array of CreateSetParams for the new quorum
        IAllocationManagerTypes.CreateSetParams[] memory createSetParams =
            new IAllocationManagerTypes.CreateSetParams[](1);

        // Initialize CreateSetParams with quorumNumber as operatorSetId
        createSetParams[0] = IAllocationManagerTypes.CreateSetParams({
            operatorSetId: operatorSetCount,
            strategies: strategies
        });
        allocationManager.createOperatorSets({ avs: avs, params: createSetParams });
    }

    function addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyOwner
    {
        require(operatorSetId <= operatorSetCount, InvalidOperatorSetId());
        allocationManager.addStrategiesToOperatorSet({
            avs: avs,
            operatorSetId: operatorSetId,
            strategies: strategies
        });
    }

    function removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyOwner
    {
        require(operatorSetId <= operatorSetCount, InvalidOperatorSetId());
        allocationManager.removeStrategiesFromOperatorSet({
            avs: avs,
            operatorSetId: operatorSetId,
            strategies: strategies
        });
    }

    /// @notice Helper function to handle operator set deregistration for OperatorSets quorums. This is used
    /// when an operator is force-deregistered from
    /// Due to deregistration being possible in the AllocationManager but not in the AVS as a result of the
    /// try/catch in `AllocationManager.deregisterFromOperatorSets`, we need to first check that the operator
    /// is not already deregistered from the OperatorSet in the AllocationManager.
    /// @param operator The operator to deregister
    /// @param operatorSetIds The operator sets to deregister the operator from
    function _forceDeregisterOperatorFromAllOperatorSets(
        address operator,
        uint32[] memory operatorSetIds
    )
        internal
        virtual
    {
        allocationManager.deregisterFromOperatorSets(
            IAllocationManagerTypes.DeregisterParams({
                operator: operator,
                avs: avs,
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

    function _setRestakingMiddleware(address _restakingMiddleware) internal {
        address prevRestakingMiddleware = restakingMiddleware;
        emit RestakingMiddlewareUpdated(prevRestakingMiddleware, _restakingMiddleware);
        restakingMiddleware = _restakingMiddleware;
    }

    /// @notice Returns the operator struct for the given `operator`
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

    function supportsRestakingMiddleware(address _restakingMiddleware)
        public
        view
        virtual
        returns (bool)
    {
        return _restakingMiddleware == address(restakingMiddleware);
    }
}
