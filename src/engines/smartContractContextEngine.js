export function smartContractContextEngine(line = "", fileName = "") {
  const normalizedLine = line.toLowerCase();
  const normalizedFile = fileName.toLowerCase();

  if (
    normalizedLine.includes("delegatecall") ||
    normalizedLine.includes("selfdestruct") ||
    normalizedLine.includes("tx.origin") ||
    normalizedLine.includes("call.value") ||
    normalizedLine.includes("assembly")
  ) {
    return {
      contextType: "Critical Execution Risk",
      riskWeight: 100,
      exploitability: "CRITICAL",
      reviewPriority: 1,
      note:
        "This line contains a high-risk Solidity primitive that should receive immediate manual review."
    };
  }

  if (
    normalizedLine.includes("upgradeto") ||
    normalizedLine.includes("upgradetoandcall") ||
    normalizedLine.includes("uupsupgradeable") ||
    normalizedLine.includes("transparentupgradeableproxy") ||
    normalizedLine.includes("implementation") ||
    normalizedLine.includes("proxy")
  ) {
    return {
      contextType: "Upgradeable Contract Risk",
      riskWeight: 85,
      exploitability: "HIGH",
      reviewPriority: 2,
      note:
        "This line may affect upgradeability, proxy behavior, or implementation control."
    };
  }

  if (
    normalizedLine.includes("onlyowner") ||
    normalizedLine.includes("default_admin_role") ||
    normalizedLine.includes("accesscontrol") ||
    normalizedLine.includes("ownable") ||
    normalizedLine.includes("admin") ||
    normalizedLine.includes("owner") ||
    normalizedLine.includes("operator") ||
    normalizedLine.includes("pauser")
  ) {
    return {
      contextType: "Admin / Permission Risk",
      riskWeight: 70,
      exploitability: "MEDIUM",
      reviewPriority: 3,
      note:
        "This line may involve privileged permissions, role control, or centralization risk."
    };
  }

  if (
    normalizedLine.includes("bridge") ||
    normalizedLine.includes("crosschain") ||
    normalizedLine.includes("cross-chain") ||
    normalizedLine.includes("layerzero") ||
    normalizedLine.includes("wormhole")
  ) {
    return {
      contextType: "Bridge / Cross-Chain Risk",
      riskWeight: 75,
      exploitability: "HIGH",
      reviewPriority: 3,
      note:
        "This line may involve cross-chain trust assumptions, bridge validation, or replay protection."
    };
  }

  if (
    normalizedLine.includes("oracle") ||
    normalizedLine.includes("pricefeed") ||
    normalizedLine.includes("aggregatorv3interface") ||
    normalizedLine.includes("latestrounddata")
  ) {
    return {
      contextType: "Oracle Dependency Risk",
      riskWeight: 65,
      exploitability: "MEDIUM",
      reviewPriority: 4,
      note:
        "This line may depend on external price or oracle data and should be reviewed for freshness and manipulation resistance."
    };
  }

  if (
    normalizedLine.includes("approve(") ||
    normalizedLine.includes("setapprovalforall") ||
    normalizedLine.includes("permit(") ||
    normalizedLine.includes("eip712") ||
    normalizedLine.includes("domain_separator")
  ) {
    return {
      contextType: "Token Approval / Signature Risk",
      riskWeight: 60,
      exploitability: "MEDIUM",
      reviewPriority: 4,
      note:
        "This line may involve approvals, signatures, replay protection, or allowance risks."
    };
  }

  if (
    normalizedLine.includes("erc20") ||
    normalizedLine.includes("erc721") ||
    normalizedLine.includes("erc1155")
  ) {
    return {
      contextType: "Token Standard Reference",
      riskWeight: 25,
      exploitability: "LOW",
      reviewPriority: 6,
      note:
        "This appears to reference a common token standard and is usually informational."
    };
  }

  if (
    normalizedFile.includes("/legacy/") ||
    normalizedFile.includes("legacy")
  ) {
    return {
      contextType: "Legacy Contract Area",
      riskWeight: 55,
      exploitability: "MEDIUM",
      reviewPriority: 5,
      note:
        "This file appears to be legacy code. Legacy areas often need extra migration and security review."
    };
  }

  return {
    contextType: "General Smart Contract Context",
    riskWeight: 40,
    exploitability: "LOW",
    reviewPriority: 7,
    note:
      "No special smart contract context detected beyond the matched rule."
  };
}
