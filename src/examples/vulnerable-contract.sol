// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = tx.origin;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }

    function emergencyDrain(address payable target) external {
        require(tx.origin == owner, "Not owner");
        selfdestruct(target);
    }

    function execute(address target, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        target.delegatecall(data);
    }
}
