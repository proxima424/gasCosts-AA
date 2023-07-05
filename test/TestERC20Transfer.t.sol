// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {Test} from "../lib/forge-std/src/Test.sol";
import {console} from "../lib/forge-std/src/console.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {SmartAccount} from "../src/SmartAccount.sol";
import {SmartAccountFactory} from "../src/SmartAccountFactory.sol";
import {EcdsaOwnershipRegistryModule} from "../src/modules/EcdsaOwnershipRegistryModule.sol";
import {SmartContractOwnershipRegistryModule} from "../src/modules/SmartContractOwnershipRegistryModule.sol";
import {UserOperation} from "../lib/account-abstraction/contracts/interfaces/UserOperation.sol";

import {ERC4337Utils} from "../src/ERC4337Utils.sol";
import {ECDSA} from "../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {IERC20} from "../lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

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

interface IECDSARegistryModule{
    function getOwner(address smartAccount) external view returns (address);
}

contract TestERC20Transfer is Test {
    using ECDSA for bytes32;
    uint256 public forkNumber;

    uint256 public smartAccountDeploymentIndex;
    address public entryPointAdr = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address public dai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address public expectedSmartAccountAddress;
    address public ecdsaOwnershipModuleAddress;
    address public smartContractOwnershipModuleAddress;
    address public smartAccountFactoryAddress;

    address public smartAccountOwner;
    uint256 public saOwnerKey;
    address public alice;
    address public bob;
    address public proxima424;
    // Address which holds >100M DAI on Ethereum Mainnet
    address public richDAI = 0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf;

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
        vm.deal(entryPointAdr,5 ether);
        vm.deal(ecdsaOwnershipModuleAddress,5 ether);
        vm.deal(smartAccountFactoryAddress,5 ether);
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
    }

    // Deployment of Smart Account with ECDSA Auth Module
    function testSmartAccountDeployment() public {
        bytes memory txnData = abi.encodeWithSignature("initForSmartAccount(address)", smartAccountOwner);
        uint256 prevGas = gasleft();
        ISAFactory(smartAccountFactoryAddress).deployCounterFactualAccount(
            ecdsaOwnershipModuleAddress, txnData, smartAccountDeploymentIndex
        );
        console.logUint(prevGas-gasleft());
        console.log("Gas required to deploy Smart Contract Wallet with ECDSA Auth Module is mentioned above: ");
    }

    function testERC20Transfer() public {
        vm.selectFork(forkNumber);

        // Get address of Smart Account in order to fund it with DAI before hand
        bytes memory txnData = abi.encodeWithSignature("initForSmartAccount(address)", smartAccountOwner);
        expectedSmartAccountAddress = ISAFactory(smartAccountFactoryAddress).getAddressForCounterFactualAccount(
            ecdsaOwnershipModuleAddress, txnData, smartAccountDeploymentIndex
        );

        // Deploy SA with smartAccountOwner as owner
        bytes memory txnData1 = abi.encodeWithSignature("initForSmartAccount(address)", smartAccountOwner);
        address userSA = ISAFactory(smartAccountFactoryAddress).deployCounterFactualAccount(
            ecdsaOwnershipModuleAddress, txnData1, smartAccountDeploymentIndex
        ); 
        
        // INVARIANT ==> SmartAccountOwner is set as owner of userSA
        assertEq(smartAccountOwner,IECDSARegistryModule(ecdsaOwnershipModuleAddress).getOwner(userSA));


        // Fund userSA and proxima424 with DAI
        vm.startPrank(richDAI);
        IERC20(dai).transfer(userSA, 5000);
        IERC20(dai).transfer(proxima424, 5000);
        vm.stopPrank();

        // INVARIANT ==> proxima424, userSA are funded with 5000 DAI each
        assertEq(IERC20(dai).balanceOf(proxima424),5000);
        assertEq(IERC20(dai).balanceOf(userSA),5000);

        // Fund userSA, entryPoint contract with 5 ether
        vm.deal(userSA,5 ether);
        vm.deal(entryPointAdr,5 ether);

        // Construct userOp to send 2500 DAI from userSA to proxima424
        uint256 amountOfDAIToSend = 2500;
        bytes memory txnData2 = abi.encodeWithSignature("transfer(address,uint256)", proxima424, amountOfDAIToSend);      
        bytes memory txnData3 = abi.encodeWithSignature("executeCall(address,uint256,bytes)", dai, 0, txnData2 );
        UserOperation memory userOp = fillUserOp(EntryPoint(payable(entryPointAdr)),userSA, txnData3);

        bytes32 hashed1 = hash(userOp);
        bytes32 hashed2 = keccak256(abi.encode(hashed1,entryPointAdr,block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(saOwnerKey,hashed2.toEthSignedMessageHash());
        bytes memory tempSignature = abi.encodePacked(r, s, v);
        userOp.signature = abi.encode(tempSignature,ecdsaOwnershipModuleAddress);
        
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;

        // Send the userOp to EntryPoint
        uint256 prevGas = gasleft();
        IEntryPoint(entryPointAdr).handleOps(ops, payable(alice));
        console.log(prevGas-gasleft());
        console.log("Gas consumed in DAI transfer is mentioned above");
        assertEq(IERC20(dai).balanceOf(proxima424),7500);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*  HELPER FUNCTIONS FOR CONSTRUCTING AND SIGNING USER-OP      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function fillUserOp(EntryPoint _entryPoint, address _sender, bytes memory _data)
        internal
        view
        returns (UserOperation memory op)
    {
        op.sender = _sender;
        op.nonce = _entryPoint.getNonce(_sender, 0);
        op.callData = _data;
        op.callGasLimit = 10000000;
        op.verificationGasLimit = 10000000;
        op.preVerificationGas = 50000;
        op.maxFeePerGas = 50000;
        op.maxPriorityFeePerGas = 1;
    }


    // 
    function getSender(UserOperation memory userOp) internal pure returns (address){
        return userOp.sender;
    }

    function pack(UserOperation memory userOp) internal pure returns (bytes memory ret) {
        address sender = getSender(userOp);
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = keccak256(userOp.initCode);
        bytes32 hashCallData = keccak256(userOp.callData);
        uint256 callGasLimit = userOp.callGasLimit;
        uint256 verificationGasLimit = userOp.verificationGasLimit;
        uint256 preVerificationGas = userOp.preVerificationGas;
        uint256 maxFeePerGas = userOp.maxFeePerGas;
        uint256 maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
        bytes32 hashPaymasterAndData = keccak256(userOp.paymasterAndData);

        return abi.encode(
            sender, nonce,
            hashInitCode, hashCallData,
            callGasLimit, verificationGasLimit, preVerificationGas,
            maxFeePerGas, maxPriorityFeePerGas,
            hashPaymasterAndData
        );
    }

    function hash(UserOperation memory userOp) internal pure returns (bytes32) {
        return keccak256(pack(userOp));
    }
}
