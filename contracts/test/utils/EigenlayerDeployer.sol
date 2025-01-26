// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import "@eigenlayer-contracts/src/contracts/core/AVSDirectory.sol";
import "@eigenlayer-contracts/src/contracts/core/DelegationManager.sol";
import "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import "forge-std/Test.sol";

import "@eigenlayer-contracts/src/contracts/interfaces/IETHPOSDeposit.sol";

import "@eigenlayer-contracts/src/contracts/core/RewardsCoordinator.sol";
import "@eigenlayer-contracts/src/contracts/core/Slasher.sol";
import "@eigenlayer-contracts/src/contracts/core/StrategyManager.sol";
import "@eigenlayer-contracts/src/contracts/strategies/StrategyBase.sol";

import "@eigenlayer-contracts/src/contracts/pods/EigenPod.sol";
import "@eigenlayer-contracts/src/contracts/pods/EigenPodManager.sol";

import "@eigenlayer-contracts/src/contracts/permissions/PauserRegistry.sol";

import "@eigenlayer-contracts/src/test/mocks/ETHDepositMock.sol";
import "@eigenlayer-contracts/src/test/mocks/EmptyContract.sol";
import "@eigenlayer-contracts/src/test/mocks/LiquidStakingToken.sol";

import "./Operator.sol";

import
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/proxy/beacon/IBeacon.sol";
import
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/proxy/beacon/UpgradeableBeacon.sol";
import
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import
    "@eigenlayer-contracts/lib/openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";

/// @dev This file is adapted from EigenLayer's test deployment contract
/// @custom:attribution
/// https://github.com/eigenfoundation/eigenlayer-contracts/blob/dbfa12128a41341b936f3e8da5d6da58c6233877/src/test/EigenLayerDeployer.t.sol
contract EigenlayerDeployer is Operators {
    Vm cheats = Vm(VM_ADDRESS);

    // EigenLayer contracts
    ProxyAdmin public eigenLayerProxyAdmin;
    PauserRegistry public eigenLayerPauserReg;

    Slasher public slasher;
    DelegationManager public delegationManager;
    AVSDirectory public avsDirectory;
    StrategyManager public strategyManager;
    EigenPodManager public eigenPodManager;
    RewardsCoordinator public rewardsCoordinator;
    IEigenPod public pod;
    IETHPOSDeposit public ethPOSDeposit;
    IBeacon public eigenPodBeacon;

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
    address slasherAddress;
    address delegationAddress;
    address strategyManagerAddress;
    address eigenPodManagerAddress;
    address podAddress;
    address eigenPodBeaconAddress;
    address emptyContractAddress;
    address operationsMultisig;
    address executorMultisig;

    address private constant rewards_coordinator_updater =
        address(0x1234567890123456789012345678901234567890);
    uint32 private constant rewards_coordinator_activation_delay = 86_400;
    uint16 private constant rewards_coordinator_default_operator_split_bips = 5000;

    // addresses excluded from fuzzing due to abnormal behavior. TODO: @Sidu28
    // define this better and give it a clearer name
    mapping(address => bool) fuzzedAddressMapping;

    //ensures that a passed in address is not set to true in the
    // fuzzedAddressMapping
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
        fuzzedAddressMapping[address(delegationManager)] = true;
        fuzzedAddressMapping[address(slasher)] = true;
    }

    function _deployEigenLayerContractsLocal() internal returns (address staker) {
        pauser = address(69);
        unpauser = address(489);
        // deploy proxy admin for ability to upgrade proxy contracts
        eigenLayerProxyAdmin = new ProxyAdmin();

        //deploy pauser registry
        address[] memory pausers = new address[](1);
        pausers[0] = pauser;
        eigenLayerPauserReg = new PauserRegistry(pausers, unpauser);

        /**
         * First, deploy upgradeable proxy contracts that **will point** to the
         * implementations. Since the implementation contracts are
         * not yet deployed, we give these proxies an empty contract as the
         * initial implementation, to act as if they have no code.
         */
        emptyContract = new EmptyContract();
        delegationManager = DelegationManager(
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
        slasher = Slasher(
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
        ethPOSDeposit = new ETHPOSDepositMock();
        pod = new EigenPod(ethPOSDeposit, eigenPodManager, GOERLI_GENESIS_TIME);

        eigenPodBeacon = new UpgradeableBeacon(address(pod));

        // Second, deploy the *implementation* contracts, using the *proxy
        // contracts* as inputs
        DelegationManager delegationImplementation =
            new DelegationManager(strategyManager, slasher, eigenPodManager);
        StrategyManager strategyManagerImplementation =
            new StrategyManager(delegationManager, eigenPodManager, slasher);
        Slasher slasherImplementation = new Slasher(strategyManager, delegationManager);
        EigenPodManager eigenPodManagerImplementation = new EigenPodManager(
            ethPOSDeposit, eigenPodBeacon, strategyManager, slasher, delegationManager
        );
        AVSDirectory avsDirectoryImplementation = new AVSDirectory(delegationManager);
        RewardsCoordinator rewardsCoordinatorImplementation = new RewardsCoordinator(
            delegationManager,
            strategyManager,
            7 days, // CALCULATION_INTERVAL_SECONDS
            365 days, // MAX_REWARDS_DURATION
            30 days, // MAX_RETROACTIVE_LENGTH
            30 days, // MAX_FUTURE_LENGTH
            uint32((block.timestamp / 7 days) * 7 days) // GENESIS_REWARDS_TIMESTAMP rounded down to nearest CALCULATION_INTERVAL_SECONDS
        );

        // Third, upgrade the proxy contracts to use the correct implementation
        // contracts and initialize them.
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(delegationManager))),
            address(delegationImplementation),
            abi.encodeWithSelector(
                DelegationManager.initialize.selector,
                eigenLayerReputedMultisig,
                eigenLayerPauserReg,
                0, /*initialPausedStatus*/
                minWithdrawalDelayBlocks,
                initializeStrategiesToSetDelayBlocks,
                initializeWithdrawalDelayBlocks
            )
        );
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(strategyManager))),
            address(strategyManagerImplementation),
            abi.encodeWithSelector(
                StrategyManager.initialize.selector,
                eigenLayerReputedMultisig,
                eigenLayerReputedMultisig,
                eigenLayerPauserReg,
                0 /*initialPausedStatus*/
            )
        );
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(slasher))),
            address(slasherImplementation),
            abi.encodeWithSelector(
                Slasher.initialize.selector,
                eigenLayerReputedMultisig,
                eigenLayerPauserReg,
                0 /*initialPausedStatus*/
            )
        );
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(avsDirectory))),
            address(avsDirectoryImplementation),
            abi.encodeWithSelector(
                AVSDirectory.initialize.selector,
                eigenLayerReputedMultisig, // initialOwner
                eigenLayerPauserReg,
                0 // initialPausedStatus
            )
        );
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(eigenPodManager))),
            address(eigenPodManagerImplementation),
            abi.encodeWithSelector(
                EigenPodManager.initialize.selector,
                eigenLayerReputedMultisig,
                eigenLayerPauserReg,
                0 /*initialPausedStatus*/
            )
        );
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(rewardsCoordinator))),
            address(rewardsCoordinatorImplementation),
            abi.encodeWithSelector(
                RewardsCoordinator.initialize.selector,
                eigenLayerReputedMultisig, // initialOwner
                eigenLayerPauserReg, // pauserRegistry
                0, // initialPausedStatus
                rewards_coordinator_updater, // rewardsUpdater
                rewards_coordinator_activation_delay, // activationDelay
                rewards_coordinator_default_operator_split_bips // defaultOperatorSplitBips
            )
        );

        //simple ERC20 (**NOT** WETH-like!), used in a test strategy
        weth =
            new ERC20PresetFixedSupply("weth", "WETH", wethInitialSupply, address(this));

        // deploy StrategyBase contract implementation, then create upgradeable
        // proxy that points to implementation and initialize it
        baseStrategyImplementation = new StrategyBase(strategyManager);
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

        IStrategy[] memory whitelistStrategies = new IStrategy[](2);
        whitelistStrategies[0] = wethStrat;
        whitelistStrategies[1] = eigenStrat;
        bool[] memory thirdPartyTransfersForbiddenValues = new bool[](2);
        thirdPartyTransfersForbiddenValues[0] = true;
        thirdPartyTransfersForbiddenValues[1] = true;
        strategyManager.addStrategiesToDepositWhitelist(
            whitelistStrategies, thirdPartyTransfersForbiddenValues
        );

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
        slasherAddress = stdJson.readAddress(config, ".addresses.slasher");
        eigenPodManagerAddress = stdJson.readAddress(config, ".addresses.eigenPodManager");
        emptyContractAddress = stdJson.readAddress(config, ".addresses.emptyContract");
        operationsMultisig = stdJson.readAddress(config, ".parameters.operationsMultisig");
        executorMultisig = stdJson.readAddress(config, ".parameters.executorMultisig");
    }
}
