// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import "../src/examples/vulnerable-contract.sol";
import "../src/examples/reetrancy-attacker.sol";
import "../src/examples/examplestx-origin-phishing.sol";
import "../src/examples/examplesdelegatecall-victim.sol";
import "../src/examples/delegatecall-takeover.sol";

contract VulnerableExamplesTest is Test {
    VulnerableVault vault;

    address owner = address(0xA11CE);
    address user = address(0xB0B);
    address attacker = address(0xBAD);

    function setUp() public {
        vm.deal(owner, 10 ether);
        vm.deal(user, 10 ether);
        vm.deal(attacker, 10 ether);

        vm.prank(owner);
        vault = new VulnerableVault();
    }

    function testDepositWorks() public {
        vm.prank(user);
        vault.deposit{value: 1 ether}();

        assertEq(vault.balances(user), 1 ether);
    }

    function testReentrancyAttackDrainsVault() public {
        vm.prank(user);
        vault.deposit{value: 5 ether}();

        vm.prank(attacker);
        ReentrancyAttacker attack =
            new ReentrancyAttacker(address(vault));

        vm.prank(attacker);
        attack.attack{value: 1 ether}();

        assertGt(address(attack).balance, 1 ether);
    }

    function testTxOriginPhishingDrain() public {
        TxOriginPhishingAttack phishing =
            new TxOriginPhishingAttack(address(vault));

        vm.prank(user);
        vault.deposit{value: 2 ether}();

        vm.prank(owner);
        phishing.trickVictim();

        assertEq(address(vault).balance, 0);
    }

    function testDelegatecallTakeover() public {
        DelegatecallVictim victim =
            new DelegatecallVictim();

        MaliciousImplementation malicious =
            new MaliciousImplementation();

        bytes memory data =
            abi.encodeWithSignature("attack()");

        victim.execute(
            address(malicious),
            data
        );

        assertEq(
            victim.owner(),
            address(this)
        );
    }
}
