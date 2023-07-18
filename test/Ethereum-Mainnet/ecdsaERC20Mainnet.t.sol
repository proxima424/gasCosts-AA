// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {Test} from "../../lib/forge-std/src/Test.sol";
import {console} from "../../lib/forge-std/src/console.sol";

// @account-abstraction core
import {UserOperation} from "../../lib/account-abstraction/contracts/interfaces/UserOperation.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {ERC4337Utils} from "../../src/ERC4337Utils.sol";

// @kernel dependencies
import {Kernel} from "@kernel/src/Kernel.sol";
import {ECDSAValidator} from "@kernel/src/validator/ECDSAValidator.sol";
import {EIP1967Proxy} from  "@kernel/src/factory/EIP1967Proxy.sol";
import {KernelFactory} from "@kernel/src/factory/KernelFactory.sol";
import {ECDSAKernelFactory} from "@kernel/src/factory/ECDSAKernelFactory.sol";

// @mocks
import {MockERC20} from "../Mocks/MockERC20.sol";

import {ECDSA} from "../../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "../../lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";


contract TestERC20 is Test {
    using ECDSA for bytes32;

    uint256 public ethFork;

    IEntryPoint public entryPoint;
    Kernel kernel;
    KernelFactory factory;
    ECDSAKernelFactory ecdsaFactory;
    ECDSAValidator validator;

    uint256 public smartAccountDeploymentIndex;
    address public entryPointAdr = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address public dai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address public userSA;

    address public smartAccountOwner;
    uint256 public saOwnerKey;
    address public alice;
    address public bob;
    address public proxima424;
    address beneficiary;
    // Address which holds >100M DAI on Ethereum Mainnet
    address public richDAI = 0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf;

    
    // SmartAccount public smartAccountImplementation;
    // SmartAccountFactory public smartAccountFactory;
    // SmartContractOwnershipRegistryModule public scwOwnershipRegistryModule;
    // EcdsaOwnershipRegistryModule public ecdsaOwnershipRegistryModule;
    MockERC20 public mockToken;

    // This function is called before every test case
    function setUp() public {
        ethFork = vm.createFork("https://eth.llamarpc.com");
        vm.selectFork(ethFork);

        // Initializes EOA Addresses
        (smartAccountOwner, saOwnerKey) = makeAddrAndKey("smartAccountOwner");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        proxima424 = makeAddr("proxima424");
        beneficiary = payable(address(makeAddr("beneficiary")));

        // Make AA Deployments
        entryPoint = IEntryPoint(payable(entryPointAdr));
        factory = new KernelFactory(entryPoint);
        validator = new ECDSAValidator();
        ecdsaFactory = new ECDSAKernelFactory(factory, validator, entryPoint);
        kernel = Kernel(payable(address(ecdsaFactory.createAccount(smartAccountOwner, smartAccountDeploymentIndex))));
        
        // Fund all contracts
        vm.deal(address(kernel), 1e30);
        vm.deal(address(factory),1e30);
        vm.deal(address(validator),1e30);
        vm.deal(address(ecdsaFactory),1e30);
    }

    // Deployment of Smart Account with ECDSA Auth Module
    function testSADeploymentWithECDSAAuth() public {
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
    function getSender(UserOperation memory userOp) internal pure returns (address) {
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
            sender,
            nonce,
            hashInitCode,
            hashCallData,
            callGasLimit,
            verificationGasLimit,
            preVerificationGas,
            maxFeePerGas,
            maxPriorityFeePerGas,
            hashPaymasterAndData
        );
    }

    function hash(UserOperation memory userOp) internal pure returns (bytes32) {
        return keccak256(pack(userOp));
    }
}
