// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {Test} from "../lib/forge-std/src/Test.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {SmartAccount} from "../src/SmartAccount.sol";
import {SmartAccountFactory} from "../src/SmartAccountFactory.sol";
import {EcdsaOwnershipRegistryModule} from "../src/modules/EcdsaOwnershipRegistryModule.sol";
import {SmartContractOwnershipRegistryModule} from "../src/modules/SmartContractOwnershipRegistryModule .sol";

import {IERC20} from "../lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract TestERC20Transfer {

    uint256 forkNumber;
    address entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address expectedSmartAccountAddress;

    address smartAccountOwner;
    address alice;
    address bob;
    address proxima424;

    IEntryPoint public entrypoint;
    SmartAccount public smartAccountImplementation;
    SmartAccountFactory public smartAccountFactory;
    SmartContractOwnershipRegistryModule public scwOwnershipRegistryModule;
    EcdsaOwnershipRegistryModule public ecdsaOwnershipRegistryModule;

    function setUp() public{
        ethFork = vm.createFork("https://eth.llamarpc.com");
        vm.selectFork(ethFork);

        entryPoint = IEntryPoint(entryPoint);
        smartAccountImplementation = new SmartAccount(entryPoint);
        smartAccountFactory = new SmartAccountFactory(address(smartAccountImplementation));
        scwOwnershipRegistryModule = new SmartContractOwnershipRegistryModule();
        ecdsaOwnershipRegistryModule = new EcdsaOwnershipRegistryModule();

        smartAccountOwner = makeAddr("smartAccountOwner");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        proxima424 = makeAddr("proxima424");
    }




}