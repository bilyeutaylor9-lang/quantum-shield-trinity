# Quantum Shield Trinity Report

## Executive Summary

**Repository Risk Level:** CRITICAL

**Security Score:** 0/100

**Security Grade:** F

**Raw Risk Score:** 100/100

**Files Scanned:** 771

**Critical Findings:** 6

**High Findings:** 0

**Medium Findings:** 0

---

## Dependency Intelligence

**Dependency Risk Level:** HIGH

**Dependency Files Scanned:** 19

**High Risk Dependencies:** 3

**Medium Risk Dependencies:** 2

### Dependency Finding #1

**Dependency:** elliptic

**File:** /Users/user/reactive-smart-contract-demos/lib/openzeppelin-contracts/package-lock.json

**Severity:** HIGH

**Category:** Lockfile Dependency Signal

**Risk:** Elliptic curve cryptography dependency detected. This may indicate ECDSA/secp256k1 usage.

**Recommendation:** Inventory signing flows and prepare a quantum migration roadmap.

---

### Dependency Finding #2

**Dependency:** crypto-js

**File:** /Users/user/reactive-smart-contract-demos/lib/openzeppelin-contracts/package-lock.json

**Severity:** MEDIUM

**Category:** Lockfile Dependency Signal

**Risk:** Crypto utility dependency detected. Review usage for SHA1, MD5, or legacy cryptography.

**Recommendation:** Audit hashing and encryption usage.

---

### Dependency Finding #3

**Dependency:** web3

**File:** /Users/user/reactive-smart-contract-demos/lib/openzeppelin-contracts/package.json

**Severity:** MEDIUM

**Category:** Blockchain Dependency

**Risk:** Web3 dependency detected. Review wallet and signing flows for crypto-agility.

**Recommendation:** Prepare signing abstractions and wallet security guidance.

---

### Dependency Finding #4

**Dependency:** elliptic

**File:** /Users/user/reactive-smart-contract-demos/lib/v2-core/yarn.lock

**Severity:** HIGH

**Category:** Lockfile Dependency Signal

**Risk:** Elliptic curve cryptography dependency detected. This may indicate ECDSA/secp256k1 usage.

**Recommendation:** Inventory signing flows and prepare a quantum migration roadmap.

---

### Dependency Finding #5

**Dependency:** elliptic

**File:** /Users/user/reactive-smart-contract-demos/lib/v2-periphery/yarn.lock

**Severity:** HIGH

**Category:** Lockfile Dependency Signal

**Risk:** Elliptic curve cryptography dependency detected. This may indicate ECDSA/secp256k1 usage.

**Recommendation:** Inventory signing flows and prepare a quantum migration roadmap.

---

---

## Attack Surface Intelligence

**Attack Surface Risk Level:** HIGH

**Attack Surface Score:** 80/100

**Total Attack Findings:** 16

**Critical Attack Paths:** 0

**High Attack Paths:** 0

**Medium Attack Paths:** 16

### Attack Surface Finding #1

**File:** /Users/user/reactive-smart-contract-demos/dashboard/contracts.js

**Line:** 4

**Type:** Hardcoded Address Risk

**Severity:** MEDIUM

**Category:** Hardcoded Blockchain Address

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

---

### Attack Surface Finding #2

**File:** /Users/user/reactive-smart-contract-demos/dashboard/contracts.js

**Line:** 5

**Type:** Hardcoded Address Risk

**Severity:** MEDIUM

**Category:** Hardcoded Blockchain Address

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

---

### Attack Surface Finding #3

**File:** /Users/user/reactive-smart-contract-demos/dashboard/contracts.js

**Line:** 6

**Type:** Hardcoded Address Risk

**Severity:** MEDIUM

**Category:** Hardcoded Blockchain Address

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

---

### Attack Surface Finding #4

**File:** /Users/user/reactive-smart-contract-demos/script/DeployAISentinel.s.sol

**Line:** 15

**Type:** Hardcoded Address Risk

**Severity:** MEDIUM

**Category:** Hardcoded Blockchain Address

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

---

### Attack Surface Finding #5

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc20-turnovers/TokenTurnoverL1.sol

**Line:** 23

**Type:** Admin Centralization Risk

**Severity:** MEDIUM

**Category:** Admin Control Risk

**Recommendation:** Review admin privileges. Consider multisig, timelocks, and role separation.

---

### Attack Surface Finding #6

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc20-turnovers/TokenTurnoverL1.sol

**Line:** 30

**Type:** Admin Centralization Risk

**Severity:** MEDIUM

**Category:** Admin Control Risk

**Recommendation:** Review admin privileges. Consider multisig, timelocks, and role separation.

---

### Attack Surface Finding #7

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc20-turnovers/TokenTurnoverReactive.sol

**Line:** 19

**Type:** Hardcoded Address Risk

**Severity:** MEDIUM

**Category:** Hardcoded Blockchain Address

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

---

### Attack Surface Finding #8

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc20-turnovers/TokenTurnoverReactive.sol

**Line:** 20

**Type:** Hardcoded Address Risk

**Severity:** MEDIUM

**Category:** Hardcoded Blockchain Address

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

---

### Attack Surface Finding #9

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc721-ownership/NftOwnershipL1.sol

**Line:** 25

**Type:** Admin Centralization Risk

**Severity:** MEDIUM

**Category:** Admin Control Risk

**Recommendation:** Review admin privileges. Consider multisig, timelocks, and role separation.

---

### Attack Surface Finding #10

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc721-ownership/NftOwnershipL1.sol

**Line:** 33

**Type:** Admin Centralization Risk

**Severity:** MEDIUM

**Category:** Admin Control Risk

**Recommendation:** Review admin privileges. Consider multisig, timelocks, and role separation.

---

### Attack Surface Finding #11

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc721-ownership/NftOwnershipReactive.sol

**Line:** 16

**Type:** Hardcoded Address Risk

**Severity:** MEDIUM

**Category:** Hardcoded Blockchain Address

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

---

### Attack Surface Finding #12

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc721-ownership/NftOwnershipReactive.sol

**Line:** 17

**Type:** Hardcoded Address Risk

**Severity:** MEDIUM

**Category:** Hardcoded Blockchain Address

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

---

### Attack Surface Finding #13

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/uniswap-v2-history/UniswapHistoryDemoL1.sol

**Line:** 26

**Type:** Admin Centralization Risk

**Severity:** MEDIUM

**Category:** Admin Control Risk

**Recommendation:** Review admin privileges. Consider multisig, timelocks, and role separation.

---

### Attack Surface Finding #14

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/uniswap-v2-history/UniswapHistoryDemoL1.sol

**Line:** 34

**Type:** Admin Centralization Risk

**Severity:** MEDIUM

**Category:** Admin Control Risk

**Recommendation:** Review admin privileges. Consider multisig, timelocks, and role separation.

---

### Attack Surface Finding #15

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/uniswap-v2-history/UniswapHistoryDemoReactive.sol

**Line:** 27

**Type:** Hardcoded Address Risk

**Severity:** MEDIUM

**Category:** Hardcoded Blockchain Address

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

---

---

## Smart Contract Audit

**Audit Risk Level:** CRITICAL

**Audit Score:** 90/100

**Audited Contracts:** 10

**Skipped Non-Production Files:** 311

**Critical Audit Findings:** 0

**High Audit Findings:** 0

**Medium Audit Findings:** 18

### Smart Contract Finding #1

**File:** /Users/user/reactive-smart-contract-demos/script/DeployAISentinel.s.sol

**Line:** 12

**Type:** Missing Access Control Signal

**Severity:** MEDIUM

**Category:** Access Control Review

**Recommendation:** Review public/external functions for required access control, validation, and rate limits.

**Context Type:** General Smart Contract Context

**Exploitability:** LOW

**Review Priority:** 7

**Context Note:** No special smart contract context detected beyond the matched rule.

---

### Smart Contract Finding #2

**File:** /Users/user/reactive-smart-contract-demos/script/DeployAISentinel.s.sol

**Line:** 15

**Type:** Hardcoded Address

**Severity:** MEDIUM

**Category:** Configuration Risk

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

**Context Type:** General Smart Contract Context

**Exploitability:** LOW

**Review Priority:** 7

**Context Note:** No special smart contract context detected beyond the matched rule.

---

### Smart Contract Finding #3

**File:** /Users/user/reactive-smart-contract-demos/src/ai-sentinel-cross-chain/aisentinelcallback.sol

**Line:** 17

**Type:** Block Timestamp Dependency

**Severity:** MEDIUM

**Category:** Time Manipulation Risk

**Recommendation:** Avoid relying on block timestamps for critical randomness, settlement, or authorization logic.

**Context Type:** General Smart Contract Context

**Exploitability:** LOW

**Review Priority:** 7

**Context Note:** No special smart contract context detected beyond the matched rule.

---

### Smart Contract Finding #4

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc20-turnovers/TokenTurnoverL1.sol

**Line:** 23

**Type:** Owner/Admin Control

**Severity:** MEDIUM

**Category:** Centralization Risk

**Recommendation:** Review owner/admin privileges. Consider multisig, timelock, and least-privilege role design.

**Context Type:** Admin / Permission Risk

**Exploitability:** MEDIUM

**Review Priority:** 3

**Context Note:** This line may involve privileged permissions, role control, or centralization risk.

---

### Smart Contract Finding #5

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc20-turnovers/TokenTurnoverL1.sol

**Line:** 30

**Type:** Owner/Admin Control

**Severity:** MEDIUM

**Category:** Centralization Risk

**Recommendation:** Review owner/admin privileges. Consider multisig, timelock, and least-privilege role design.

**Context Type:** Admin / Permission Risk

**Exploitability:** MEDIUM

**Review Priority:** 3

**Context Note:** This line may involve privileged permissions, role control, or centralization risk.

---

### Smart Contract Finding #6

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc20-turnovers/TokenTurnoverReactive.sol

**Line:** 67

**Type:** Missing Access Control Signal

**Severity:** MEDIUM

**Category:** Access Control Review

**Recommendation:** Review public/external functions for required access control, validation, and rate limits.

**Context Type:** Legacy Contract Area

**Exploitability:** MEDIUM

**Review Priority:** 5

**Context Note:** This file appears to be legacy code. Legacy areas often need extra migration and security review.

---

### Smart Contract Finding #7

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc20-turnovers/TokenTurnoverReactive.sol

**Line:** 19

**Type:** Hardcoded Address

**Severity:** MEDIUM

**Category:** Configuration Risk

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

**Context Type:** Token Standard Reference

**Exploitability:** LOW

**Review Priority:** 6

**Context Note:** This appears to reference a common token standard and is usually informational.

---

### Smart Contract Finding #8

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc20-turnovers/TokenTurnoverReactive.sol

**Line:** 20

**Type:** Hardcoded Address

**Severity:** MEDIUM

**Category:** Configuration Risk

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

**Context Type:** Legacy Contract Area

**Exploitability:** MEDIUM

**Review Priority:** 5

**Context Note:** This file appears to be legacy code. Legacy areas often need extra migration and security review.

---

### Smart Contract Finding #9

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc721-ownership/NftOwnershipL1.sol

**Line:** 25

**Type:** Owner/Admin Control

**Severity:** MEDIUM

**Category:** Centralization Risk

**Recommendation:** Review owner/admin privileges. Consider multisig, timelock, and least-privilege role design.

**Context Type:** Admin / Permission Risk

**Exploitability:** MEDIUM

**Review Priority:** 3

**Context Note:** This line may involve privileged permissions, role control, or centralization risk.

---

### Smart Contract Finding #10

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc721-ownership/NftOwnershipL1.sol

**Line:** 33

**Type:** Owner/Admin Control

**Severity:** MEDIUM

**Category:** Centralization Risk

**Recommendation:** Review owner/admin privileges. Consider multisig, timelock, and least-privilege role design.

**Context Type:** Admin / Permission Risk

**Exploitability:** MEDIUM

**Review Priority:** 3

**Context Note:** This line may involve privileged permissions, role control, or centralization risk.

---

### Smart Contract Finding #11

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc721-ownership/NftOwnershipReactive.sol

**Line:** 64

**Type:** Missing Access Control Signal

**Severity:** MEDIUM

**Category:** Access Control Review

**Recommendation:** Review public/external functions for required access control, validation, and rate limits.

**Context Type:** Legacy Contract Area

**Exploitability:** MEDIUM

**Review Priority:** 5

**Context Note:** This file appears to be legacy code. Legacy areas often need extra migration and security review.

---

### Smart Contract Finding #12

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc721-ownership/NftOwnershipReactive.sol

**Line:** 16

**Type:** Hardcoded Address

**Severity:** MEDIUM

**Category:** Configuration Risk

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

**Context Type:** Token Standard Reference

**Exploitability:** LOW

**Review Priority:** 6

**Context Note:** This appears to reference a common token standard and is usually informational.

---

### Smart Contract Finding #13

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc721-ownership/NftOwnershipReactive.sol

**Line:** 17

**Type:** Hardcoded Address

**Severity:** MEDIUM

**Category:** Configuration Risk

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

**Context Type:** Legacy Contract Area

**Exploitability:** MEDIUM

**Review Priority:** 5

**Context Note:** This file appears to be legacy code. Legacy areas often need extra migration and security review.

---

### Smart Contract Finding #14

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/uniswap-v2-history/UniswapHistoryDemoL1.sol

**Line:** 26

**Type:** Owner/Admin Control

**Severity:** MEDIUM

**Category:** Centralization Risk

**Recommendation:** Review owner/admin privileges. Consider multisig, timelock, and least-privilege role design.

**Context Type:** Admin / Permission Risk

**Exploitability:** MEDIUM

**Review Priority:** 3

**Context Note:** This line may involve privileged permissions, role control, or centralization risk.

---

### Smart Contract Finding #15

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/uniswap-v2-history/UniswapHistoryDemoL1.sol

**Line:** 34

**Type:** Owner/Admin Control

**Severity:** MEDIUM

**Category:** Centralization Risk

**Recommendation:** Review owner/admin privileges. Consider multisig, timelock, and least-privilege role design.

**Context Type:** Admin / Permission Risk

**Exploitability:** MEDIUM

**Review Priority:** 3

**Context Note:** This line may involve privileged permissions, role control, or centralization risk.

---

### Smart Contract Finding #16

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/uniswap-v2-history/UniswapHistoryDemoReactive.sol

**Line:** 74

**Type:** Missing Access Control Signal

**Severity:** MEDIUM

**Category:** Access Control Review

**Recommendation:** Review public/external functions for required access control, validation, and rate limits.

**Context Type:** Legacy Contract Area

**Exploitability:** MEDIUM

**Review Priority:** 5

**Context Note:** This file appears to be legacy code. Legacy areas often need extra migration and security review.

---

### Smart Contract Finding #17

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/uniswap-v2-history/UniswapHistoryDemoReactive.sol

**Line:** 27

**Type:** Hardcoded Address

**Severity:** MEDIUM

**Category:** Configuration Risk

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

**Context Type:** Legacy Contract Area

**Exploitability:** MEDIUM

**Review Priority:** 5

**Context Note:** This file appears to be legacy code. Legacy areas often need extra migration and security review.

---

### Smart Contract Finding #18

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/uniswap-v2-history/UniswapHistoryDemoReactive.sol

**Line:** 28

**Type:** Hardcoded Address

**Severity:** MEDIUM

**Category:** Configuration Risk

**Recommendation:** Verify hardcoded addresses are intentional, documented, and network-specific.

**Context Type:** Legacy Contract Area

**Exploitability:** MEDIUM

**Review Priority:** 5

**Context Note:** This file appears to be legacy code. Legacy areas often need extra migration and security review.

---

---

## Security Copilot Recommendations

### Copilot Finding #1

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc20-turnovers/TokenTurnoverReactive.sol

**Line:** 19

**Type:** Ethereum Private Key

**Severity:** CRITICAL

**Risk:** Potential Ethereum private key detected.

**Business Impact:** If valid, this can lead to complete wallet compromise and asset loss.

**Recommendation:** Treat the key as compromised. Move funds to a new wallet and remove it from the repository.

**Migration Path:** Hardcoded wallet key → Hardware wallet, vault, or environment secret

**Estimated Effort:** Immediate

---

### Copilot Finding #2

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc20-turnovers/TokenTurnoverReactive.sol

**Line:** 20

**Type:** Ethereum Private Key

**Severity:** CRITICAL

**Risk:** Potential Ethereum private key detected.

**Business Impact:** If valid, this can lead to complete wallet compromise and asset loss.

**Recommendation:** Treat the key as compromised. Move funds to a new wallet and remove it from the repository.

**Migration Path:** Hardcoded wallet key → Hardware wallet, vault, or environment secret

**Estimated Effort:** Immediate

---

### Copilot Finding #3

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc721-ownership/NftOwnershipReactive.sol

**Line:** 16

**Type:** Ethereum Private Key

**Severity:** CRITICAL

**Risk:** Potential Ethereum private key detected.

**Business Impact:** If valid, this can lead to complete wallet compromise and asset loss.

**Recommendation:** Treat the key as compromised. Move funds to a new wallet and remove it from the repository.

**Migration Path:** Hardcoded wallet key → Hardware wallet, vault, or environment secret

**Estimated Effort:** Immediate

---

### Copilot Finding #4

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/erc721-ownership/NftOwnershipReactive.sol

**Line:** 17

**Type:** Ethereum Private Key

**Severity:** CRITICAL

**Risk:** Potential Ethereum private key detected.

**Business Impact:** If valid, this can lead to complete wallet compromise and asset loss.

**Recommendation:** Treat the key as compromised. Move funds to a new wallet and remove it from the repository.

**Migration Path:** Hardcoded wallet key → Hardware wallet, vault, or environment secret

**Estimated Effort:** Immediate

---

### Copilot Finding #5

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/uniswap-v2-history/UniswapHistoryDemoReactive.sol

**Line:** 27

**Type:** Ethereum Private Key

**Severity:** CRITICAL

**Risk:** Potential Ethereum private key detected.

**Business Impact:** If valid, this can lead to complete wallet compromise and asset loss.

**Recommendation:** Treat the key as compromised. Move funds to a new wallet and remove it from the repository.

**Migration Path:** Hardcoded wallet key → Hardware wallet, vault, or environment secret

**Estimated Effort:** Immediate

---

### Copilot Finding #6

**File:** /Users/user/reactive-smart-contract-demos/src/legacy/uniswap-v2-history/UniswapHistoryDemoReactive.sol

**Line:** 28

**Type:** Ethereum Private Key

**Severity:** CRITICAL

**Risk:** Potential Ethereum private key detected.

**Business Impact:** If valid, this can lead to complete wallet compromise and asset loss.

**Recommendation:** Treat the key as compromised. Move funds to a new wallet and remove it from the repository.

**Migration Path:** Hardcoded wallet key → Hardware wallet, vault, or environment secret

**Estimated Effort:** Immediate

---

---

## Disclaimer

Quantum Shield Trinity is an experimental security research tool. Findings should be reviewed by a qualified developer or security professional before production changes are made.
