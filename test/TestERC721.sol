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
import {MockERC721} from "./Mocks/MockERC721.sol";

import {ERC4337Utils} from "../src/ERC4337Utils.sol";
import {ECDSA} from "../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";


import {IERC721} from "../lib/openzeppelin-contracts/contracts/interfaces/IERC721.sol";
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


contract TestERC721 is Test {

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
    MockERC721 public mockERC721;

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
        mockERC721 = new MockERC721("Mock","Mock");
        
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

        // Deploy SA with smartAccountOwner as owner and fund it with 5 ether
        bytes memory txnData1 = abi.encodeWithSignature("initForSmartAccount(address)", smartAccountOwner);
        userSA = ISAFactory(smartAccountFactoryAddress).deployCounterFactualAccount(
            ecdsaOwnershipModuleAddress, txnData1, smartAccountDeploymentIndex
        );
        vm.deal(userSA,5 ether);
    }

    function testERC721TransferCold() public{
        // Mint userSA an NFT with tokeniD 0
        mockERC721.mint(userSA,0);

        // Construct userOp to send ERC721from userSA to proxima424
        bytes memory txnData = abi.encodeWithSignature("transfer(address,uint256)", proxima424,0);      
        bytes memory txnData1 = abi.encodeWithSignature("executeCall(address,uint256,bytes)", address(mockERC721), 0, txnData );
        UserOperation memory userOp = fillUserOp(EntryPoint(payable(entryPointAdr)),userSA, txnData1);

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
        console.log("ECDSA Module :: Gas consumed in NFT transfer (cold access) is mentioned above");
        // INVARIANT := NFT tokenId 0 transferred from userSA to proxima424
        assertEq(mockERC721.ownerOf(0),proxima424);
    }

    function testERC721TransferWarm() public{
        // Mint userSA,proxima424 an NFT with tokeniD 0,1 
        mockERC721.mint(userSA,0);
        mockERC721.mint(proxima424,1);

        // Construct userOp to send ERC721from userSA to proxima424
        bytes memory txnData = abi.encodeWithSignature("transfer(address,uint256)", proxima424,0);      
        bytes memory txnData1 = abi.encodeWithSignature("executeCall(address,uint256,bytes)", address(mockERC721), 0, txnData );
        UserOperation memory userOp = fillUserOp(EntryPoint(payable(entryPointAdr)),userSA, txnData1);

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
        console.log("ECDSA Module :: Gas consumed in NFT transfer (warm access) is mentioned above");
        // NFT with tokenId 0 is transferred from userSA to proxima424 ( holds another NFT already)
        assertEq(mockERC721.ownerOf(0),proxima424);
    }

    function testERC721MintCold() public{
        // Construct userOp to mint ERC721 to userSA 
        bytes memory txnData = abi.encodeWithSignature("mint(address,uint256)", userSA,0);      
        bytes memory txnData1 = abi.encodeWithSignature("executeCall(address,uint256,bytes)", address(mockERC721), 0, txnData );
        UserOperation memory userOp = fillUserOp(EntryPoint(payable(entryPointAdr)),userSA, txnData1);

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
        console.log("ECDSA Module :: Gas consumed in minting NFT (cold access) is mentioned above");
        // NFT with tokenId 0 is minted to userSA
        assertEq(mockERC721.ownerOf(0),userSA);
    }

    function testERC721MintWarm() public{
        // Mint NFT to userSA to make the storage slot warm
        mockERC721.mint(userSA,0);

        // Construct userOp to mint ERC721 to userSA 
        bytes memory txnData = abi.encodeWithSignature("mint(address,uint256)", userSA, 1);      
        bytes memory txnData1 = abi.encodeWithSignature("executeCall(address,uint256,bytes)", address(mockERC721), 0, txnData );
        UserOperation memory userOp = fillUserOp(EntryPoint(payable(entryPointAdr)),userSA, txnData1);

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
        console.log("ECDSA Module :: Gas consumed in minting NFT (warm access) is mentioned above");
        // NFT with tokenId 0 is minted to userSA
        assertEq(mockERC721.ownerOf(1),userSA);
    }

    function testERC721ApproveWarm() public{
        // Mint NFT to userSA and approve proxima424
        // To make the _tokenApproval[0] storage slot warm
        mockERC721.mint(userSA,0);
        vm.startPrank(userSA);
        mockERC721.approve(proxima424,0);
        vm.stopPrank();
        assertEq(mockERC721.getApproved(0),proxima424);

        // Construct userOp to approve Alice of ERC721 tokenId 0
        bytes memory txnData = abi.encodeWithSignature("approve(address,uint256)", alice, 0);      
        bytes memory txnData1 = abi.encodeWithSignature("executeCall(address,uint256,bytes)", address(mockERC721), 0, txnData );
        UserOperation memory userOp = fillUserOp(EntryPoint(payable(entryPointAdr)),userSA, txnData1);

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
        console.log("ECDSA Module :: Gas consumed in approving NFT (warm access) is mentioned above");
        // NFT with tokenId 0 is minted to userSA
        assertEq(mockERC721.getApproved(0), alice);
    }

    function testERC721ApproveCold() public{
        // Mint NFT to userSA
        mockERC721.mint(userSA,0);

        // Construct userOp to approve proxima424 of ERC721 tokenId 0
        bytes memory txnData = abi.encodeWithSignature("approve(address,uint256)", proxima424, 0);      
        bytes memory txnData1 = abi.encodeWithSignature("executeCall(address,uint256,bytes)", address(mockERC721), 0, txnData );
        UserOperation memory userOp = fillUserOp(EntryPoint(payable(entryPointAdr)),userSA, txnData1);

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
        console.log("ECDSA Module :: Gas consumed in approving NFT (cold access) is mentioned above");
        // NFT with tokenId 0 is minted to userSA
        assertEq(mockERC721.getApproved(0), proxima424);
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
