// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {Test} from "../../lib/forge-std/src/Test.sol";
import {console} from "../../lib/forge-std/src/console.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {SmartAccount} from "../../src/SmartAccount.sol";
import {SmartAccountFactory} from "../../src/SmartAccountFactory.sol";
import {EcdsaOwnershipRegistryModule} from "../../src/modules/EcdsaOwnershipRegistryModule.sol";
import {SmartContractOwnershipRegistryModule} from "../../src/modules/SmartContractOwnershipRegistryModule.sol";
import {UserOperation} from "../../lib/account-abstraction/contracts/interfaces/UserOperation.sol";

import {ERC4337Utils} from "../../src/ERC4337Utils.sol";
import {ECDSA} from "../../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {IERC20} from "../../lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {INonceManager} from "@account-abstraction/contracts/interfaces/INonceManager.sol";

interface ISAFactory {
    function deployCounterFactualAccount(address moduleSetupContract, bytes calldata moduleSetupData, uint256 index)
        external
        returns (address proxy);

    function deployAccount(address moduleSetupContract, bytes calldata moduleSetupData)
        external
        returns (address proxy);

    function getAddressForCounterFactualAccount(
        address moduleSetupContract,
        bytes calldata moduleSetupData,
        uint256 index
    ) external view returns (address _account);
}

interface IECDSARegistryModule {
    function getOwner(address smartAccount) external view returns (address);
}

contract TestTemplate is Test {
    using ECDSA for bytes32;

    uint256 public forkNumber;

    uint256 public smartAccountDeploymentIndex;
    address public entryPointAdr = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address public userSA;
    address public ecdsaOwnershipModuleAddress;
    address public smartContractOwnershipModuleAddress;
    address public smartAccountFactoryAddress;

    address public smartAccountOwner;
    uint256 public saOwnerKey;
    address public alice;
    address public bob;
    address public proxima424;

    IEntryPoint public entryPoint;
    SmartAccount public smartAccountImplementation;
    SmartAccountFactory public smartAccountFactory;
    SmartContractOwnershipRegistryModule public scwOwnershipRegistryModule;
    EcdsaOwnershipRegistryModule public ecdsaOwnershipRegistryModule;

    // This function is called before every test case
    function setUp() public {
        forkNumber = vm.createFork("https://eth.llamarpc.com");
        vm.selectFork(forkNumber);

        // Make AA Deployments
        entryPoint = IEntryPoint(payable(entryPointAdr));
        smartAccountImplementation = new SmartAccount(entryPoint);
        smartAccountFactory = new SmartAccountFactory(address(smartAccountImplementation));
        scwOwnershipRegistryModule = new SmartContractOwnershipRegistryModule();
        ecdsaOwnershipRegistryModule = new EcdsaOwnershipRegistryModule();

        // Fund all contracts
        vm.deal(entryPointAdr, 5 ether);
        vm.deal(ecdsaOwnershipModuleAddress, 5 ether);
        vm.deal(smartAccountFactoryAddress, 5 ether);
        vm.deal(smartContractOwnershipModuleAddress, 5 ether);

        // Set Addresses
        ecdsaOwnershipModuleAddress = address(ecdsaOwnershipRegistryModule);
        smartContractOwnershipModuleAddress = address(scwOwnershipRegistryModule);
        smartAccountFactoryAddress = address(smartAccountFactory);

        // Initializes EOA Addresses
        (smartAccountOwner, saOwnerKey) = makeAddrAndKey("smartAccountOwner");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        proxima424 = makeAddr("proxima424");

        // Deploy SA with smartAccountOwner as owner and fund it with 5 ether
        bytes memory txnData1 = abi.encodeWithSignature("initForSmartAccount(address)", smartAccountOwner);
        userSA = ISAFactory(smartAccountFactoryAddress).deployCounterFactualAccount(
            ecdsaOwnershipModuleAddress, txnData1, smartAccountDeploymentIndex
        );
        vm.deal(userSA, 5 ether);

        vm.startPrank(userSA);
        INonceManager(entryPointAdr).incrementNonce(0);
        vm.stopPrank();
    }
}
