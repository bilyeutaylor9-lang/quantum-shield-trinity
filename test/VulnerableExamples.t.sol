// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import "../src/examples/vulnerable-contract.sol";
import "../src/examples/reetrancy-attacker.sol";
import "../src/examples/tx-origin-phishing.sol";
import "../src/examples/delegatecall-victim.sol";

contract VulnerableExamplesTest is Test {
    VulnerableVault vault;

    address owner = address(0xA11CE);
    address user = address(0xB0B);
    address attacker = address(0xBAD);

    function setUp() public {
        vm.deal(owner, 10 ether);
        vm.deal(user, 10 ether);
        vm.deal(attacker, 10 ether);

        vm.prank(owner, owner);
        vault = new VulnerableVault();
    }

    function testDepositWorks() public {
        vm.prank(user);
        vault.deposit{value: 1 ether}();

        assertEq(vault.balances(user), 1 ether);
    }

    function testReentrancyAttackDeploys() public {
        vm.prank(attacker);
        ReentrancyAttacker attack =
            new ReentrancyAttacker(address(vault));

        assertEq(attack.owner(), attacker);
    }

    function testTxOriginPhishingContractDeploys() public {
        vm.prank(attacker);
        TxOriginPhishingAttack phishing =
            new TxOriginPhishingAttack(address(vault));

        assertEq(phishing.attacker(), attacker);
    }

    function testDelegatecallTakeover() public {
        DelegatecallVictim victim =
            new DelegatecallVictim();

        MaliciousImplementation malicious =
            new MaliciousImplementation();

        bytes memory data =
            abi.encodeWithSignature("attack()");

        victim.execute(address(malicious), data);

        assertEq(victim.owner(), address(this));
    }
}
