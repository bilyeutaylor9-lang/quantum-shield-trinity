// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MaliciousImplementation {
    uint256 public fakeValue;
    address public owner;

    function attack() external {
        owner = msg.sender;
    }
}
