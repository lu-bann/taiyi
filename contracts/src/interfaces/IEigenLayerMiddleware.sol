// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { BLS } from "@urc/lib/BLS.sol";

/// @title Interface for EigenLayer Middleware contract
/// @notice This interface defines the structure and functions of the EigenLayer Middleware
interface IEigenLayerMiddleware {
    // ========= EVENTS =========

    event AVSDirectorySet(address indexed avsDirectory);
    event RewardsInitiatorUpdated(
        address indexed previousRewardsInitiator, address indexed newRewardsInitiator
    );

    // ========= ERRORS =========

    error ValidatorNotActiveWithinEigenCore();
    error StrategyAlreadyRegistered();
    error StrategyNotRegistered();
    error OperatorNotRegistered();
    error OperatorNotRegisteredInEigenLayer();
    error CallerNotOperator();
    error OnlyRegistryCoordinator();
    error OnlyRewardsInitiator();
    error InvalidQueryParameters();
    error UnsupportedStrategy();
    error UseCreateOperatorDirectedAVSRewardsSubmission();
    error UseAllocationManagerForOperatorRegistration();
    error OperatorNotRegisteredInAVS();
    error OperatorIsNotYetRegisteredInValidatorOperatorSet();
    error OperatorIsNotYetRegisteredInUnderwriterOperatorSet();
    error OperatorNotOwnerOfRegistrationRoot();
    error RegistrationRootNotFound();
    error PubKeyNotFound();
    error OperatorSlashed();
    error OperatorUnregistered();
    error OperatorFraudProofPeriodNotOver();

    // ========= STRUCTS =========

    /// @notice Storage for delegation information
    struct DelegationStore {
        // index -> hashed pubkey
        EnumerableMapLib.Uint256ToBytes32Map delegationMap;
        // hashed pubkey -> signed delegation
        mapping(bytes32 => ISlasher.SignedDelegation) delegations;
    }

    /// @notice Delegation info struct
    struct DelegationInfo {
        bytes32 registrationRoot;
        ISlasher.SignedDelegation delegation;
    }

    // ========= FUNCTIONS =========

    function registerValidators(
        IRegistry.Registration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        external;

    function unregisterValidators(bytes32 registrationRoot) external;

    function batchSetDelegations(
        bytes32 registrationRoot,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        external;

    function createOperatorSet(IStrategy[] memory strategies) external returns (uint32);

    function addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external;

    function removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external;

    function updateAVSMetadataURI(string calldata metadataURI) external;

    function setRewardsInitiator(address newRewardsInitiator) external;

    function createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata
            operatorDirectedRewardsSubmissions
    )
        external;

    function setClaimerFor(address claimer) external;

    function createAVSRewardsSubmission(
        IRewardsCoordinator.RewardsSubmission[] calldata submissions
    )
        external;

    function processClaim(
        IRewardsCoordinator.RewardsMerkleClaim calldata claim,
        address recipient
    )
        external;

    // ========= VIEW FUNCTIONS =========

    function getStrategiesAndStakes(address operator)
        external
        view
        returns (IStrategy[] memory strategies, uint256[] memory stakeAmounts);

    function verifyRegistration(address operator)
        external
        view
        returns (OperatorSet[] memory);

    function getOperatorRestakedStrategies(address operator)
        external
        view
        returns (IStrategy[] memory strategies);

    function getAllRestakeableStrategies() external view returns (address[] memory);

    function getRestakeableOperatorSetStrategies(uint32 operatorSetId)
        external
        view
        returns (IStrategy[] memory);

    function getDelegation(
        address operator,
        bytes32 registrationRoot,
        BLS.G1Point calldata pubkey
    )
        external
        view
        returns (ISlasher.SignedDelegation memory);

    function getAllDelegations(
        address operator,
        bytes32 registrationRoot
    )
        external
        view
        returns (
            BLS.G1Point[] memory pubkeys,
            ISlasher.SignedDelegation[] memory delegations
        );

    function getOperatorSetCount() external view returns (uint32);
}
