// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";


contract Deployments{

    function deployEntryPoint() public returns(address){
        return address(new EntryPoint());
    }

}