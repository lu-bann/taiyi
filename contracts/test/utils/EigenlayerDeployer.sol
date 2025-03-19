// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import "@eigenlayer-contracts/src/contracts/core/AVSDirectory.sol";

import "@eigenlayer-contracts/src/contracts/core/AllocationManager.sol";
import "@eigenlayer-contracts/src/contracts/core/DelegationManager.sol";

import "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import "@eigenlayer-contracts/src/contracts/permissions/PermissionController.sol";
import "forge-std/StdJson.sol";

import "forge-std/Test.sol";

import "@eigenlayer-contracts/src/contracts/core/RewardsCoordinator.sol";
import "@eigenlayer-contracts/src/contracts/core/StrategyManager.sol";
import "@eigenlayer-contracts/src/contracts/interfaces/IETHPOSDeposit.sol";
import "@eigenlayer-contracts/src/contracts/strategies/StrategyBase.sol";
import "@eigenlayer-contracts/src/contracts/strategies/StrategyBaseTVLLimits.sol";

import "@eigenlayer-contracts/src/contracts/pods/EigenPod.sol";
import "@eigenlayer-contracts/src/contracts/pods/EigenPodManager.sol";

import "@eigenlayer-contracts/src/contracts/permissions/PauserRegistry.sol";

import "@eigenlayer-contracts/src/test/mocks/ETHDepositMock.sol";
import "@eigenlayer-contracts/src/test/mocks/EmptyContract.sol";
import "@eigenlayer-contracts/src/test/mocks/LiquidStakingToken.sol";

import "./Operator.sol";

import
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/proxy/beacon/UpgradeableBeacon.sol";
import
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/proxy/transparent/ProxyAdmin.sol";
import
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";

/// @dev This file is adapted from EigenLayer's test deployment contract
/// @custom:attribution
/// https://github.com/eigenfoundation/eigenlayer-contracts/blob/dbfa12128a41341b936f3e8da5d6da58c6233877/src/test/EigenLayerDeployer.t.sol
contract EigenlayerDeployer is Operators {
    Vm cheats = Vm(VM_ADDRESS);

    struct StrategyConfig {
        uint256 maxDeposits;
        uint256 maxPerDeposit;
        address tokenAddress;
        string tokenSymbol;
    }

    // Change from array to mapping for storage efficiency
    mapping(uint256 => StrategyConfig) public strategyConfigs;
    uint256 public strategyConfigsCount;
    StrategyBaseTVLLimits[] public deployedStrategyArray;

    // EigenLayer contracts
    ProxyAdmin public eigenLayerProxyAdmin;
    PauserRegistry public eigenLayerPauserReg;

    AllocationManager public allocationManager;
    PermissionController public permissionController;
    DelegationManager public delegation;
    AVSDirectory public avsDirectory;
    StrategyManager public strategyManager;
    EigenPodManager public eigenPodManager;
    RewardsCoordinator public rewardsCoordinator;
    IEigenPod public eigenPodImplementation;
    IETHPOSDeposit public ethPOSDeposit;
    UpgradeableBeacon public eigenPodBeacon;

    // testing/mock contracts
    IERC20 public eigenToken;
    IERC20 public weth;
    StrategyBase public wethStrat;
    StrategyBase public eigenStrat;
    StrategyBase public baseStrategyImplementation;
    EmptyContract public emptyContract;

    mapping(uint256 => IStrategy) public strategies;

    //from testing seed phrase
    bytes32 priv_key_0 =
        0x1234567812345678123456781234567812345678123456781234567812345678;
    bytes32 priv_key_1 =
        0x1234567812345678123456781234567812345698123456781234567812348976;

    //strategy indexes for undelegation (see commitUndelegation function)
    uint256[] public strategyIndexes;
    address[2] public stakers;
    address sample_registrant = cheats.addr(436_364_636);

    address[] public slashingContracts;

    uint256 wethInitialSupply = 10e50;
    uint256 public constant eigenTotalSupply = 1000e18;
    uint256 nonce = 69;
    uint256 public gasLimit = 750_000;
    IStrategy[] public initializeStrategiesToSetDelayBlocks;
    uint256[] public initializeWithdrawalDelayBlocks;
    uint256 minWithdrawalDelayBlocks = 0;
    uint32 PARTIAL_WITHDRAWAL_FRAUD_PROOF_PERIOD_BLOCKS = 7 days / 12 seconds;
    uint256 REQUIRED_BALANCE_WEI = 32 ether;
    uint64 MAX_PARTIAL_WTIHDRAWAL_AMOUNT_GWEI = 1 ether / 1e9;
    uint64 GOERLI_GENESIS_TIME = 1_616_508_000;
    uint32 MIN_WITHDRAWAL_DELAY = 86_400;

    address pauser;
    address unpauser;
    address theMultiSig = address(420);
    address operator = address(0x4206904396bF2f8b173350ADdEc5007A52664293);
    address acct_0 = cheats.addr(uint256(priv_key_0));
    address acct_1 = cheats.addr(uint256(priv_key_1));
    address _challenger = address(0x6966904396bF2f8b173350bCcec5007A52669873);
    address public eigenLayerReputedMultisig = address(this);

    address eigenLayerProxyAdminAddress;
    address eigenLayerPauserRegAddress;
    address delegationAddress;
    address strategyManagerAddress;
    address eigenPodManagerAddress;
    address podAddress;
    address eigenPodBeaconAddress;
    address emptyContractAddress;
    address operationsMultisig;

    // Configuration variables read from JSON
    bytes public strategyConfigsRaw;
    uint32 public REWARDS_COORDINATOR_CALCULATION_INTERVAL_SECONDS;
    uint32 public REWARDS_COORDINATOR_MAX_REWARDS_DURATION;
    uint32 public REWARDS_COORDINATOR_MAX_RETROACTIVE_LENGTH;
    uint32 public REWARDS_COORDINATOR_MAX_FUTURE_LENGTH;
    uint32 public REWARDS_COORDINATOR_GENESIS_REWARDS_TIMESTAMP;
    uint32 public DEALLOCATION_DELAY;
    uint32 public ALLOCATION_CONFIGURATION_DELAY;
    uint256 public DELEGATION_INIT_PAUSED_STATUS;
    uint256 public DELEGATION_WITHDRAWAL_DELAY_BLOCKS;
    uint256 public STRATEGY_MANAGER_INIT_PAUSED_STATUS;
    uint256 public EIGENPOD_MANAGER_INIT_PAUSED_STATUS;
    uint256 public REWARDS_COORDINATOR_INIT_PAUSED_STATUS;
    address public REWARDS_COORDINATOR_UPDATER;
    uint32 public REWARDS_COORDINATOR_ACTIVATION_DELAY;
    uint32 public REWARDS_COORDINATOR_GLOBAL_OPERATOR_COMMISSION_BIPS;
    uint256 public ALLOCATION_MANAGER_INIT_PAUSED_STATUS;
    address public executorMultisig;
    address public pauserMultisig;

    // addresses excluded from fuzzing due to abnormal behavior
    mapping(address => bool) fuzzedAddressMapping;

    modifier fuzzedAddress(address addr) virtual {
        cheats.assume(fuzzedAddressMapping[addr] == false);
        _;
    }

    modifier cannotReinit() {
        cheats.expectRevert(bytes("Initializable: contract is already initialized"));
        _;
    }

    //performs basic deployment before each test
    function setUp() public virtual returns (address staker) {
        // Read and parse config
        operatorConfigJson =
            vm.readFile("./test/test-data/deploy_from_scratch.anvil.config.json");
        strategyConfigsRaw = stdJson.parseRaw(operatorConfigJson, ".strategies");

        // Decode into a memory array first
        StrategyConfig[] memory configs =
            abi.decode(strategyConfigsRaw, (StrategyConfig[]));

        // Convert to mapping
        for (uint256 i = 0; i < configs.length; i++) {
            addStrategyConfig(
                configs[i].maxDeposits,
                configs[i].maxPerDeposit,
                configs[i].tokenAddress,
                configs[i].tokenSymbol
            );
        }

        // Initialize configuration variables
        REWARDS_COORDINATOR_CALCULATION_INTERVAL_SECONDS = uint32(
            stdJson.readUint(
                operatorConfigJson, ".rewardsCoordinator.calculation_interval_seconds"
            )
        );
        REWARDS_COORDINATOR_MAX_REWARDS_DURATION = uint32(
            stdJson.readUint(
                operatorConfigJson, ".rewardsCoordinator.MAX_REWARDS_DURATION"
            )
        );
        REWARDS_COORDINATOR_MAX_RETROACTIVE_LENGTH = uint32(
            stdJson.readUint(
                operatorConfigJson, ".rewardsCoordinator.MAX_RETROACTIVE_LENGTH"
            )
        );
        REWARDS_COORDINATOR_MAX_FUTURE_LENGTH = uint32(
            stdJson.readUint(operatorConfigJson, ".rewardsCoordinator.MAX_FUTURE_LENGTH")
        );
        REWARDS_COORDINATOR_GENESIS_REWARDS_TIMESTAMP = uint32(
            stdJson.readUint(
                operatorConfigJson, ".rewardsCoordinator.GENESIS_REWARDS_TIMESTAMP"
            )
        );
        DEALLOCATION_DELAY = uint32(
            stdJson.readUint(operatorConfigJson, ".allocationManager.DEALLOCATION_DELAY")
        );
        ALLOCATION_CONFIGURATION_DELAY = uint32(
            stdJson.readUint(
                operatorConfigJson, ".allocationManager.ALLOCATION_CONFIGURATION_DELAY"
            )
        );
        DELEGATION_INIT_PAUSED_STATUS =
            stdJson.readUint(operatorConfigJson, ".delegation.init_paused_status");
        DELEGATION_WITHDRAWAL_DELAY_BLOCKS = stdJson.readUint(
            operatorConfigJson, ".delegation.init_withdrawal_delay_blocks"
        );
        STRATEGY_MANAGER_INIT_PAUSED_STATUS =
            stdJson.readUint(operatorConfigJson, ".strategyManager.init_paused_status");
        EIGENPOD_MANAGER_INIT_PAUSED_STATUS =
            stdJson.readUint(operatorConfigJson, ".eigenPodManager.init_paused_status");
        REWARDS_COORDINATOR_INIT_PAUSED_STATUS =
            stdJson.readUint(operatorConfigJson, ".rewardsCoordinator.init_paused_status");
        REWARDS_COORDINATOR_UPDATER = stdJson.readAddress(
            operatorConfigJson, ".rewardsCoordinator.rewards_updater_address"
        );
        REWARDS_COORDINATOR_ACTIVATION_DELAY = uint32(
            stdJson.readUint(operatorConfigJson, ".rewardsCoordinator.activation_delay")
        );
        REWARDS_COORDINATOR_GLOBAL_OPERATOR_COMMISSION_BIPS = uint32(
            stdJson.readUint(
                operatorConfigJson, ".rewardsCoordinator.global_operator_commission_bips"
            )
        );
        ALLOCATION_MANAGER_INIT_PAUSED_STATUS =
            stdJson.readUint(operatorConfigJson, ".allocationManager.init_paused_status");

        executorMultisig = stdJson.readAddress(
            operatorConfigJson, ".multisig_addresses.executorMultisig"
        );
        operationsMultisig = stdJson.readAddress(
            operatorConfigJson, ".multisig_addresses.operationsMultisig"
        );
        pauserMultisig =
            stdJson.readAddress(operatorConfigJson, ".multisig_addresses.pauserMultisig");

        // Deploy contracts
        try vm.envUint("CHAIN_ID") returns (uint256 chainId) {
            if (chainId == 31_337) {
                staker = _deployEigenLayerContractsLocal();
            }
            // If CHAIN_ID ENV is not set, assume local deployment on 31337
        } catch {
            staker = _deployEigenLayerContractsLocal();
        }

        fuzzedAddressMapping[address(0)] = true;
        fuzzedAddressMapping[address(eigenLayerProxyAdmin)] = true;
        fuzzedAddressMapping[address(strategyManager)] = true;
        fuzzedAddressMapping[address(eigenPodManager)] = true;
        fuzzedAddressMapping[address(rewardsCoordinator)] = true;
        fuzzedAddressMapping[address(delegation)] = true;
    }

    function _deployEigenLayerContractsLocal() internal returns (address staker) {
        pauser = address(69);
        unpauser = address(489);
        // deploy proxy admin for ability to upgrade proxy contracts
        eigenLayerProxyAdmin = new ProxyAdmin();

        //deploy pauser registry
        {
            address[] memory pausers = new address[](3);
            pausers[0] = executorMultisig;
            pausers[1] = operationsMultisig;
            pausers[2] = pauserMultisig;
            eigenLayerPauserReg = new PauserRegistry(pausers, executorMultisig);
        }

        /**
         * First, deploy upgradeable proxy contracts that **will point** to the
         * implementations. Since the implementation contracts are
         * not yet deployed, we give these proxies an empty contract as the
         * initial implementation, to act as if they have no code.
         */
        emptyContract = new EmptyContract();
        delegation = DelegationManager(
            address(
                new TransparentUpgradeableProxy(
                    address(emptyContract), address(eigenLayerProxyAdmin), ""
                )
            )
        );
        strategyManager = StrategyManager(
            address(
                new TransparentUpgradeableProxy(
                    address(emptyContract), address(eigenLayerProxyAdmin), ""
                )
            )
        );
        avsDirectory = AVSDirectory(
            address(
                new TransparentUpgradeableProxy(
                    address(emptyContract), address(eigenLayerProxyAdmin), ""
                )
            )
        );
        eigenPodManager = EigenPodManager(
            address(
                new TransparentUpgradeableProxy(
                    address(emptyContract), address(eigenLayerProxyAdmin), ""
                )
            )
        );
        rewardsCoordinator = RewardsCoordinator(
            address(
                new TransparentUpgradeableProxy(
                    address(emptyContract), address(eigenLayerProxyAdmin), ""
                )
            )
        );
        allocationManager = AllocationManager(
            address(
                new TransparentUpgradeableProxy(
                    address(emptyContract), address(eigenLayerProxyAdmin), ""
                )
            )
        );
        permissionController = PermissionController(
            address(
                new TransparentUpgradeableProxy(
                    address(emptyContract), address(eigenLayerProxyAdmin), ""
                )
            )
        );

        ethPOSDeposit = IETHPOSDeposit(
            stdJson.readAddress(operatorConfigJson, ".ethPOSDepositAddress")
        );
        eigenPodImplementation =
            new EigenPod(ethPOSDeposit, eigenPodManager, GOERLI_GENESIS_TIME);

        eigenPodBeacon = new UpgradeableBeacon(address(eigenPodImplementation));

        // Second, deploy the *implementation* contracts, using the *proxy
        // contracts* as inputs
        DelegationManager delegationImplementation = new DelegationManager(
            strategyManager,
            eigenPodManager,
            allocationManager,
            eigenLayerPauserReg,
            permissionController,
            MIN_WITHDRAWAL_DELAY
        );
        StrategyManager strategyManagerImplementation =
            new StrategyManager(delegation, eigenLayerPauserReg);
        AVSDirectory avsDirectoryImplementation =
            new AVSDirectory(delegation, eigenLayerPauserReg);
        EigenPodManager eigenPodManagerImplementation = new EigenPodManager(
            ethPOSDeposit, eigenPodBeacon, delegation, eigenLayerPauserReg
        );
        RewardsCoordinator rewardsCoordinatorImplementation = new RewardsCoordinator(
            delegation,
            strategyManager,
            allocationManager,
            eigenLayerPauserReg,
            permissionController,
            REWARDS_COORDINATOR_CALCULATION_INTERVAL_SECONDS,
            REWARDS_COORDINATOR_MAX_REWARDS_DURATION,
            REWARDS_COORDINATOR_MAX_RETROACTIVE_LENGTH,
            REWARDS_COORDINATOR_MAX_FUTURE_LENGTH,
            REWARDS_COORDINATOR_GENESIS_REWARDS_TIMESTAMP
        );

        AllocationManager allocationManagerImplementation = new AllocationManager(
            delegation,
            eigenLayerPauserReg,
            permissionController,
            DEALLOCATION_DELAY,
            ALLOCATION_CONFIGURATION_DELAY
        );
        PermissionController permissionControllerImplementation =
            new PermissionController();

        // Third, upgrade the proxy contracts to use the correct implementation
        // contracts and initialize them.

        {
            IStrategy[] memory _strategies;
            uint256[] memory _withdrawalDelayBlocks;
            eigenLayerProxyAdmin.upgradeAndCall(
                ITransparentUpgradeableProxy(payable(address(delegation))),
                address(delegationImplementation),
                abi.encodeWithSelector(
                    DelegationManager.initialize.selector,
                    executorMultisig,
                    DELEGATION_INIT_PAUSED_STATUS,
                    DELEGATION_WITHDRAWAL_DELAY_BLOCKS,
                    _strategies,
                    _withdrawalDelayBlocks
                )
            );
        }
        eigenLayerProxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(payable(address(strategyManager))),
            address(strategyManagerImplementation),
            abi.encodeWithSelector(
                StrategyManager.initialize.selector,
                executorMultisig,
                operationsMultisig,
                STRATEGY_MANAGER_INIT_PAUSED_STATUS
            )
        );

        // Grant strategy whitelisting permission to executorMultisig
        vm.startPrank(executorMultisig);
        strategyManager.setStrategyWhitelister(executorMultisig);
        vm.stopPrank();

        eigenLayerProxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(payable(address(avsDirectory))),
            address(avsDirectoryImplementation),
            abi.encodeWithSelector(AVSDirectory.initialize.selector, executorMultisig, 0)
        );
        eigenLayerProxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(payable(address(eigenPodManager))),
            address(eigenPodManagerImplementation),
            abi.encodeWithSelector(
                EigenPodManager.initialize.selector,
                executorMultisig,
                EIGENPOD_MANAGER_INIT_PAUSED_STATUS
            )
        );
        eigenLayerProxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(payable(address(rewardsCoordinator))),
            address(rewardsCoordinatorImplementation),
            abi.encodeWithSelector(
                RewardsCoordinator.initialize.selector,
                executorMultisig,
                REWARDS_COORDINATOR_INIT_PAUSED_STATUS,
                REWARDS_COORDINATOR_UPDATER,
                REWARDS_COORDINATOR_ACTIVATION_DELAY,
                REWARDS_COORDINATOR_GLOBAL_OPERATOR_COMMISSION_BIPS
            )
        );
        eigenLayerProxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(payable(address(allocationManager))),
            address(allocationManagerImplementation),
            abi.encodeWithSelector(
                AllocationManager.initialize.selector,
                executorMultisig,
                ALLOCATION_MANAGER_INIT_PAUSED_STATUS
            )
        );
        eigenLayerProxyAdmin.upgrade(
            ITransparentUpgradeableProxy(payable(address(permissionController))),
            address(permissionControllerImplementation)
        );

        // // deploy StrategyBaseTVLLimits contract implementation
        // baseStrategyImplementation = new StrategyBaseTVLLimits(strategyManager, eigenLayerPauserReg);
        // // create upgradeable proxies that each point to the implementation and initialize them
        // for (uint256 i = 0; i < strategyConfigs.length; ++i) {
        //     if (strategyConfigs[i].tokenAddress == address(0)) {
        //         strategyConfigs[i].tokenAddress = address(new ERC20PresetFixedSupply("TestToken", "TEST", uint256(type(uint128).max), executorMultisig));
        //     }
        //     deployedStrategyArray.push(
        //         StrategyBaseTVLLimits(
        //             address(
        //                 new TransparentUpgradeableProxy(
        //                     address(baseStrategyImplementation),
        //                     address(eigenLayerProxyAdmin),
        //                     abi.encodeWithSelector(
        //                         StrategyBaseTVLLimits.initialize.selector,
        //                         strategyConfigs[i].maxPerDeposit,
        //                         strategyConfigs[i].maxDeposits,
        //                         IERC20(strategyConfigs[i].tokenAddress)
        //                     )
        //                 )
        //             )
        //         )
        //     );
        // }

        //simple ERC20 (**NOT** WETH-like!), used in a test strategy
        weth =
            new ERC20PresetFixedSupply("weth", "WETH", wethInitialSupply, address(this));

        // deploy StrategyBase contract implementation, then create upgradeable
        // proxy that points to implementation and initialize it
        baseStrategyImplementation =
            new StrategyBase(strategyManager, eigenLayerPauserReg);
        wethStrat = StrategyBase(
            address(
                new TransparentUpgradeableProxy(
                    address(baseStrategyImplementation),
                    address(eigenLayerProxyAdmin),
                    abi.encodeWithSelector(
                        StrategyBase.initialize.selector, weth, eigenLayerPauserReg
                    )
                )
            )
        );

        eigenToken =
            new ERC20PresetFixedSupply("eigen", "EIGEN", wethInitialSupply, address(this));

        // deploy upgradeable proxy that points to StrategyBase implementation
        // and initialize it
        eigenStrat = StrategyBase(
            address(
                new TransparentUpgradeableProxy(
                    address(baseStrategyImplementation),
                    address(eigenLayerProxyAdmin),
                    abi.encodeWithSelector(
                        StrategyBase.initialize.selector, eigenToken, eigenLayerPauserReg
                    )
                )
            )
        );

        // Whitelist strategies
        vm.startPrank(executorMultisig);
        IStrategy[] memory whitelistStrategies = new IStrategy[](2);
        whitelistStrategies[0] = wethStrat;
        whitelistStrategies[1] = eigenStrat;
        bool[] memory thirdPartyTransfersForbiddenValues = new bool[](2);
        thirdPartyTransfersForbiddenValues[0] = true;
        thirdPartyTransfersForbiddenValues[1] = true;
        strategyManager.addStrategiesToDepositWhitelist(whitelistStrategies);
        vm.stopPrank();

        staker = acct_0;
        weth.transfer(staker, 100 ether);
    }

    function _setAddresses(string memory config) internal {
        eigenLayerProxyAdminAddress =
            stdJson.readAddress(config, ".addresses.eigenLayerProxyAdmin");
        eigenLayerPauserRegAddress =
            stdJson.readAddress(config, ".addresses.eigenLayerPauserReg");
        delegationAddress = stdJson.readAddress(config, ".addresses.delegation");
        strategyManagerAddress = stdJson.readAddress(config, ".addresses.strategyManager");
        eigenPodManagerAddress = stdJson.readAddress(config, ".addresses.eigenPodManager");
        emptyContractAddress = stdJson.readAddress(config, ".addresses.emptyContract");
        operationsMultisig = stdJson.readAddress(config, ".parameters.operationsMultisig");
        executorMultisig = stdJson.readAddress(config, ".parameters.executorMultisig");
    }

    function addStrategyConfig(
        uint256 maxDeposits,
        uint256 maxPerDeposit,
        address tokenAddress,
        string memory tokenSymbol
    )
        internal
    {
        strategyConfigs[strategyConfigsCount] = StrategyConfig({
            maxDeposits: maxDeposits,
            maxPerDeposit: maxPerDeposit,
            tokenAddress: tokenAddress,
            tokenSymbol: tokenSymbol
        });
        strategyConfigsCount++;
    }
}
