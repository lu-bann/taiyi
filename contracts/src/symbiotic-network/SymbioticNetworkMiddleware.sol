// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

import { EIP712Upgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/utils/cryptography/EIP712Upgradeable.sol";

import { IERC20 } from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import { Math } from "@openzeppelin-contracts/contracts/utils/math/Math.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { IBaseDelegator } from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";

import { Subnetworks } from "@symbiotic-middleware-sdk/extensions/Subnetworks.sol";

import { OzAccessManaged } from
    "@symbiotic-middleware-sdk/extensions/managers/access/OzAccessManaged.sol";
import { EpochCapture } from
    "@symbiotic-middleware-sdk/extensions/managers/capture-timestamps/EpochCapture.sol";
import { KeyManagerAddress } from
    "@symbiotic-middleware-sdk/extensions/managers/keys/KeyManagerAddress.sol";
import { EqualStakePower } from
    "@symbiotic-middleware-sdk/extensions/managers/stake-powers/EqualStakePower.sol";
import { Operators } from "@symbiotic-middleware-sdk/extensions/operators/Operators.sol";

import { SelfRegisterOperators } from
    "@symbiotic-middleware-sdk/extensions/operators/SelfRegisterOperators.sol";
import { Subnetwork } from "@symbiotic/contracts/libraries/Subnetwork.sol";

import { INetworkRegistry } from "@symbiotic/interfaces/INetworkRegistry.sol";
import { IVault } from "@symbiotic/interfaces/vault/IVault.sol";

import { ServiceTypeLib } from "../libs/ServiceTypeLib.sol";

/// @title SymbioticNetworkMiddleware
/// @notice A unified middleware contract that manages both gateway and validator networks in the Symbiotic ecosystem
/// @dev Implements subnetwork functionality to handle both gateway and validator operators
contract SymbioticNetworkMiddleware is
    KeyManagerAddress,
    EpochCapture,
    EqualStakePower,
    OzAccessManaged,
    Operators,
    Subnetworks
{
    using EnumerableSet for EnumerableSet.AddressSet;
    using Subnetwork for address;
    using ServiceTypeLib for ITaiyiRegistryCoordinator.RestakingServiceTypes;

    error InvalidSignature();
    error NoVaultsToSlash();
    error InactiveSubnetworkSlash();
    error InactiveKeySlash();
    error InactiveOperatorSlash();

    ITaiyiRegistryCoordinator public registryCoordinator;

    uint96 public constant VALIDATOR_SUBNETWORK = 1;
    uint96 public constant UNDERWRITER_SUBNETWORK = 2;

    struct SlashParams {
        uint48 timestamp;
        bytes key;
        uint256 amount;
        bytes32 subnetwork;
        bytes[] slashHints;
    }

    /// @notice Disables initializers for the implementation contract
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract with required parameters and setup subnetworks
    /// @param network The address of the network
    /// @param slashingWindow The duration of the slashing window
    /// @param vaultRegistry The address of the vault registry
    /// @param operatorRegistry The address of the operator registry
    /// @param operatorNetOptIn The address of the operator network opt-in service
    /// @param reader The address of the reader contract used for delegatecall
    /// @param owner The address of the contract owner
    /// @param _registryCoordinator The address of the registry coordinator
    /// @param _epochDuration The duration of the epoch
    /// @dev Calls BaseMiddleware.init and Subnetworks.registerSubnetwork
    function initialize(
        address network,
        uint48 slashingWindow,
        address vaultRegistry,
        address operatorRegistry,
        address operatorNetOptIn,
        address reader,
        address owner,
        address _registryCoordinator,
        uint48 _epochDuration
    )
        external
        initializer
    {
        __BaseMiddleware_init(
            network,
            slashingWindow,
            vaultRegistry,
            operatorRegistry,
            operatorNetOptIn,
            reader
        );
        __OzAccessManaged_init(owner);
        __EpochCapture_init(_epochDuration);

        registryCoordinator = ITaiyiRegistryCoordinator(_registryCoordinator);
    }

    function setupSubnetworks() external {
        super.registerSubnetwork(VALIDATOR_SUBNETWORK);
        super.registerSubnetwork(UNDERWRITER_SUBNETWORK);
    }

    /// @notice Register a new operator with the specified key, vault, and subnetwork
    /// @param key The address key of the operator
    /// @param vault The vault address associated with the operator
    /// @param signature The signature proving ownership of the key
    /// @param subnetwork The subnetwork identifier (VALIDATOR_SUBNETWORK or UNDERWRITER_SUBNETWORK)
    /// @dev Calls BaseOperators._registerOperatorImpl
    function registerOperator(
        bytes memory key,
        address vault,
        bytes memory signature,
        uint96 subnetwork
    )
        external
    {
        require(
            subnetwork == VALIDATOR_SUBNETWORK || subnetwork == UNDERWRITER_SUBNETWORK,
            "Invalid subnetwork"
        );

        _verifyKey(msg.sender, key, signature);
        super._registerOperatorImpl(msg.sender, key, vault);

        ITaiyiRegistryCoordinator.RestakingServiceTypes serviceType = subnetwork
            == VALIDATOR_SUBNETWORK
            ? ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_VALIDATOR
            : ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_UNDERWRITER;
        uint32 serviceTypeId = serviceType.toId();

        registryCoordinator.registerOperatorWithServiceType(
            msg.sender, serviceTypeId, bytes("")
        );
    }

    /// @notice Unregister the calling operator from the system
    /// @dev Calls BaseOperators._unregisterOperatorImpl
    function unregisterOperator() external {
        super._unregisterOperatorImpl(msg.sender);
        //registryCoordinator.deregisterOperator(msg.sender);
    }

    /// @notice Pause the calling operator's operations
    /// @dev Calls BaseOperators._pauseOperatorImpl
    function pauseOperator() external {
        super._pauseOperatorImpl(msg.sender);
    }

    /// @notice Unpause the calling operator's operations
    /// @dev Calls BaseOperators._unpauseOperatorImpl
    function unpauseOperator() external {
        super._unpauseOperatorImpl(msg.sender);
    }

    /// @notice Register a vault for the calling operator
    /// @param vault The address of the vault to register
    /// @dev Calls BaseOperators._registerOperatorVaultImpl
    function registerOperatorVault(address vault) external {
        if (!super._isOperatorRegistered(msg.sender)) {
            revert OperatorNotRegistered();
        }
        super._registerOperatorVaultImpl(msg.sender, vault);
    }

    /// @notice Unregister a vault from the calling operator
    /// @param vault The address of the vault to unregister
    /// @dev Calls BaseOperators._unregisterOperatorVaultImpl
    function unregisterOperatorVault(address vault) external {
        super._unregisterOperatorVaultImpl(msg.sender, vault);
    }

    /// @notice Pause a specific vault for the calling operator
    /// @param vault The address of the vault to pause
    /// @dev Calls BaseOperators._pauseOperatorVaultImpl
    function pauseOperatorVault(address vault) external {
        super._pauseOperatorVaultImpl(msg.sender, vault);
    }

    /// @notice Unpause a specific vault for the calling operator
    /// @param vault The address of the vault to unpause
    /// @dev Calls BaseOperators._unpauseOperatorVaultImpl
    function unpauseOperatorVault(address vault) external {
        super._unpauseOperatorVaultImpl(msg.sender, vault);
    }

    /// @notice Slashes an operator's stake across their active vaults
    /// @param params The parameters for the slash operation including key, timestamp, subnetwork, amount and hints
    /// @dev Verifies the operator and their vaults are active, calculates proportional slash amounts, and executes slashing
    /// @dev Slashing is distributed proportionally based on stake amounts in each vault
    /// @dev The final vault receives any remaining dust amount from rounding
    /// @dev TODO: This implementation treats all collateral equally across vaults. Should consider collateral value differences.
    function slash(SlashParams calldata params) external {
        address operator = _getOperatorAndCheckCanSlash(params.key, params.timestamp);
        address[] memory vaults = super._activeVaultsAt(params.timestamp, operator);

        if (vaults.length == 0) revert NoVaultsToSlash();

        uint256 totalStake;
        uint256[] memory stakes = new uint256[](vaults.length);

        // Calculate total stake across all vaults
        for (uint256 i; i < vaults.length; ++i) {
            stakes[i] = IBaseDelegator(IVault(vaults[i]).delegator()).stakeAt(
                params.subnetwork, operator, params.timestamp, params.slashHints[i]
            );
            totalStake += stakes[i];
        }

        if (totalStake == 0) revert NoVaultsToSlash();

        uint256 remainingAmount = params.amount;
        uint256[] memory slashAmounts = new uint256[](vaults.length);

        // Calculate proportional amounts using safe math
        for (uint256 i; i < vaults.length; ++i) {
            slashAmounts[i] = Math.mulDiv(params.amount, stakes[i], totalStake);
            remainingAmount -= slashAmounts[i];
        }

        // Distribute remaining amount due to rounding errors
        if (remainingAmount > 0) {
            slashAmounts[vaults.length - 1] += remainingAmount;
        }

        // Execute slashing with safety checks
        for (uint256 i; i < vaults.length; ++i) {
            if (slashAmounts[i] > 0) {
                _slashVault(
                    params.timestamp,
                    vaults[i],
                    params.subnetwork,
                    operator,
                    slashAmounts[i],
                    params.slashHints[i]
                );
            }
        }
    }

    /// @notice Gets the list of active operators at a specific timestamp
    /// @param timestamp The timestamp
    /// @return The list of active operators at the given timestamp
    /// @dev Calls BaseOperators._activeOperatorsAt
    function activeOperatorsAt(uint48 timestamp)
        external
        view
        returns (address[] memory)
    {
        return super._activeOperatorsAt(timestamp);
    }

    /// @notice Checks if an operator was active at a specific timestamp
    /// @param timestamp The timestamp
    /// @param operator The operator address
    /// @return True if the operator was active at the given timestamp, false otherwise
    /// @dev Calls BaseOperators._operatorWasActiveAt
    function operatorWasActiveAt(
        uint48 timestamp,
        address operator
    )
        external
        view
        returns (bool)
    {
        return super._operatorWasActiveAt(timestamp, operator);
    }

    /// @notice Checks if an operator is registered
    /// @param operator The operator address
    /// @return True if the operator is registered, false otherwise
    /// @dev Calls BaseOperators._isOperatorRegistered
    function isOperatorRegistered(address operator) external view returns (bool) {
        return super._isOperatorRegistered(operator);
    }

    /// @notice Gets the list of active vaults for a specific operator
    /// @param operator The operator address
    /// @return The list of active vaults for the given operator
    /// @dev Calls BaseOperators._activeOperatorVaults
    function activeOperatorVaults(address operator)
        external
        view
        returns (address[] memory)
    {
        return super._activeOperatorVaults(operator);
    }

    /// @notice Gets the list of active vaults for a specific operator at a specific timestamp
    /// @param timestamp The timestamp
    /// @param operator The operator address
    /// @return The list of active vaults for the given operator at the given timestamp
    /// @dev Calls BaseOperators._activeOperatorVaultsAt
    function activeOperatorVaultsAt(
        uint48 timestamp,
        address operator
    )
        external
        view
        returns (address[] memory)
    {
        return super._activeOperatorVaultsAt(timestamp, operator);
    }

    /// @notice Gets the list of active vaults
    /// @return The list of active vaults
    /// @dev Calls BaseOperators._activeVaults
    function activeVaults() external view returns (address[] memory) {
        return super._activeVaults();
    }

    /// @notice Gets the list of active vaults at a specific timestamp
    /// @param timestamp The timestamp
    /// @return The list of active vaults at the given timestamp
    /// @dev Calls BaseOperators._activeVaultsAt
    function activeVaultsAt(uint48 timestamp) external view returns (address[] memory) {
        return super._activeVaultsAt(timestamp);
    }

    /// @notice Gets the list of active vaults for a specific operator
    /// @param operator The operator address
    /// @return The list of active vaults for the given operator
    /// @dev Calls BaseOperators._activeVaults
    function activeVaults(address operator) external view returns (address[] memory) {
        return super._activeVaults(operator);
    }

    /// @notice Gets the list of active vaults for a specific operator at a specific timestamp
    /// @param timestamp The timestamp
    /// @param operator The operator address
    /// @return The list of active vaults for the given operator at the given timestamp
    /// @dev Calls BaseOperators._activeVaultsAt
    function activeVaultsAt(
        uint48 timestamp,
        address operator
    )
        external
        view
        returns (address[] memory)
    {
        return super._activeVaultsAt(timestamp, operator);
    }

    /// @notice Retrieves the collateral tokens and their staked quantities for a given operator's active vaults
    /// @param operator Address of the operator whose collateral stakes will be queried
    /// @return vaults Array of vault addresses
    /// @return collateralTokens Array of collateral token addresses corresponding to each vault
    /// @return stakedAmounts Array of staked amounts corresponding to each vault
    function getOperatorCollaterals(address operator)
        external
        view
        returns (
            address[] memory vaults,
            address[] memory collateralTokens,
            uint256[] memory stakedAmounts
        )
    {
        address[] memory activeVaultAddresses = super._activeOperatorVaults(operator);
        uint256 length = activeVaultAddresses.length;

        vaults = new address[](length);
        collateralTokens = new address[](length);
        stakedAmounts = new uint256[](length);

        for (uint256 i = 0; i < length; i++) {
            address vault = activeVaultAddresses[i];
            vaults[i] = vault;
            collateralTokens[i] = IVault(vault).collateral();

            uint256 validatorPower =
                super._getOperatorPower(operator, vault, VALIDATOR_SUBNETWORK);
            uint256 underwriterPower =
                super._getOperatorPower(operator, vault, UNDERWRITER_SUBNETWORK);
            stakedAmounts[i] = validatorPower + underwriterPower;
        }

        return (vaults, collateralTokens, stakedAmounts);
    }

    /// @notice Gets the power of an operator for a specific vault and subnetwork
    /// @param operator The operator address
    /// @param vault The vault address
    /// @param subnetwork The subnetwork address
    /// @return The power of the operator for the given vault and subnetwork
    /// @dev Calls BaseOperators._getOperatorPower
    function getOperatorPower(
        address operator,
        address vault,
        uint96 subnetwork
    )
        external
        view
        returns (uint256)
    {
        return super._getOperatorPower(operator, vault, subnetwork);
    }

    /// @notice Gets the power of an operator for a specific vault and subnetwork at a specific timestamp
    /// @param timestamp The timestamp
    /// @param operator The operator address
    /// @param vault The vault address
    /// @param subnetwork The subnetwork address
    /// @return The power of the operator for the given vault and subnetwork at the given timestamp
    /// @dev Calls BaseOperators._getOperatorPowerAt
    function getOperatorPowerAt(
        uint48 timestamp,
        address operator,
        address vault,
        uint96 subnetwork
    )
        external
        view
        returns (uint256)
    {
        return super._getOperatorPowerAt(timestamp, operator, vault, subnetwork);
    }

    /// @notice Gets the power of an operator
    /// @param operator The operator address
    /// @return The power of the operator
    /// @dev Calls BaseOperators._getOperatorPower
    function getOperatorPower(address operator) external view returns (uint256) {
        return super._getOperatorPower(operator);
    }

    function getOperatorByKey(bytes memory key) external view returns (address) {
        return super.operatorByKey(key);
    }

    /// @notice Gets the power of an operator for specific vaults and subnetworks at a specific timestamp
    /// @param timestamp The timestamp
    /// @param operator The operator address
    /// @param vaults The list of vault addresses
    /// @param subnetworks The list of subnetwork addresses
    /// @return The power of the operator for the given vaults and subnetworks at the given timestamp
    /// @dev Calls BaseOperators._getOperatorPowerAt
    function getOperatorPowerAt(
        uint48 timestamp,
        address operator,
        address[] memory vaults,
        uint160[] memory subnetworks
    )
        external
        view
        returns (uint256)
    {
        return super._getOperatorPowerAt(timestamp, operator, vaults, subnetworks);
    }

    /// @notice Gets the total power of a list of operators
    /// @param operators The list of operator addresses
    /// @return The total power of the given operators
    /// @dev Calls _totalPower
    function totalPower(address[] memory operators) external view returns (uint256) {
        return _totalPower(operators);
    }

    /// @notice Internal function to verify operator's address key signature
    /// @param operator The operator address
    /// @param key The address key
    /// @param signature The signature to verify
    function _verifyKey(
        address operator,
        bytes memory key,
        bytes memory signature
    )
        internal
        view
    {
        // For address-based verification, we expect the key to be an encoded address
        // and the signature to be empty or a valid ECDSA signature
        address keyAddress = abi.decode(key, (address));

        // Simple verification: Check that the key address matches the operator or that the key
        // is a valid signer for the operator
        if (keyAddress != operator) {
            // Additional verification could be added here if needed
            // For now, we'll just check if the key address matches the operator
            revert InvalidSignature();
        }
    }

    /// @notice Gets the operator address for a given key and verifies they can be slashed
    /// @param key The address key to look up
    /// @param timestamp The timestamp to check activity at
    /// @return operator The operator address associated with the key
    /// @dev Verifies both the key and operator were active at the given timestamp
    function _getOperatorAndCheckCanSlash(
        bytes memory key,
        uint48 timestamp
    )
        internal
        view
        returns (address operator)
    {
        operator = super.operatorByKey(key);
        if (!super.keyWasActiveAt(timestamp, key)) revert InactiveKeySlash();
        if (!super._operatorWasActiveAt(timestamp, operator)) {
            revert InactiveOperatorSlash();
        }
    }
}
