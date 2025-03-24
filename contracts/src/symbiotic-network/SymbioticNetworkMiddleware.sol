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

import { IProposerRegistry } from "../interfaces/IProposerRegistry.sol";
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

import { IEntity } from "@symbiotic/interfaces/common/IEntity.sol";
import { ISlasher } from "@symbiotic/interfaces/slasher/ISlasher.sol";
import { IVetoSlasher } from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import { IVault } from "@symbiotic/interfaces/vault/IVault.sol";

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

    error InvalidSignature();
    error NoVaultsToSlash();
    error InactiveSubnetworkSlash();
    error InactiveKeySlash();
    error InactiveOperatorSlash();

    IProposerRegistry public proposerRegistry;

    uint96 public constant VALIDATOR_SUBNETWORK = 1;
    uint96 public constant GATEWAY_SUBNETWORK = 2;

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
    /// @param _proposerRegistry The address of the proposer registry contract
    /// @dev Calls BaseMiddleware.init and Subnetworks.registerSubnetwork
    function initialize(
        address network,
        uint48 slashingWindow,
        address vaultRegistry,
        address operatorRegistry,
        address operatorNetOptIn,
        address reader,
        address owner,
        address _proposerRegistry,
        uint48 epochDuration
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
        __EpochCapture_init(epochDuration);

        proposerRegistry = IProposerRegistry(_proposerRegistry);
    }

    function setupSubnetworks() external {
        super.registerSubnetwork(VALIDATOR_SUBNETWORK);
        super.registerSubnetwork(GATEWAY_SUBNETWORK);
    }

    /// @notice Register a new operator with the specified key, vault, and subnetwork
    /// @param key The address key of the operator
    /// @param vault The vault address associated with the operator
    /// @param signature The signature proving ownership of the key
    /// @param subnetwork The subnetwork identifier (VALIDATOR_SUBNETWORK or GATEWAY_SUBNETWORK)
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
            subnetwork == VALIDATOR_SUBNETWORK || subnetwork == GATEWAY_SUBNETWORK,
            "Invalid subnetwork"
        );

        _verifyKey(msg.sender, key, signature);
        super._registerOperatorImpl(msg.sender, key, vault);

        IProposerRegistry.RestakingServiceType serviceType = subnetwork
            == VALIDATOR_SUBNETWORK
            ? IProposerRegistry.RestakingServiceType.SYMBIOTIC_VALIDATOR
            : IProposerRegistry.RestakingServiceType.SYMBIOTIC_GATEWAY;

        proposerRegistry.registerOperator(msg.sender, serviceType, bytes(""));
    }

    /// @notice Unregister the calling operator from the system
    /// @dev Calls BaseOperators._unregisterOperatorImpl
    function unregisterOperator() external {
        super._unregisterOperatorImpl(msg.sender);
        proposerRegistry.deregisterOperator(msg.sender);
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
                // Get the slasher from the vault
                address slasher = IVault(vaults[i]).slasher();
                if (slasher == address(0)) {
                    revert("No slasher");
                }

                // Get the slasher type from the entity
                uint64 slasherType = IEntity(slasher).TYPE();

                // Call the appropriate slasher based on its type
                if (slasherType == uint64(1)) {
                    // Instant slasher type
                    ISlasher(slasher).slash(
                        params.subnetwork,
                        operator,
                        slashAmounts[i],
                        params.timestamp,
                        params.slashHints[i]
                    );
                } else if (slasherType == uint64(2)) {
                    // Veto slasher type
                    IVetoSlasher(slasher).requestSlash(
                        params.subnetwork,
                        operator,
                        slashAmounts[i],
                        params.timestamp,
                        params.slashHints[i]
                    );
                } else {
                    revert("Unknown slasher type");
                }
            }
        }
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
            uint256 gatewayPower =
                super._getOperatorPower(operator, vault, GATEWAY_SUBNETWORK);
            stakedAmounts[i] = validatorPower + gatewayPower;
        }

        return (vaults, collateralTokens, stakedAmounts);
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

    /// @notice Internal function to update operator's address key
    /// @param key The new address key
    /// @param signature The signature proving ownership of the new key
    function _updateOperatorKey(bytes memory key, bytes memory signature) internal {
        _verifyKey(msg.sender, key, signature);
        super._updateOperatorKeyImpl(msg.sender, key);
        proposerRegistry.updateOperatorBLSKey(msg.sender, key);
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
