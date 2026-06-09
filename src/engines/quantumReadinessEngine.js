export function quantumReadinessEngine(files = []) {
  const findings = [];
  const inventory = {
    rsa: 0,
    ecc: 0,
    ecdsa: 0,
    secp256k1: 0,
    sha1: 0,
    sha256: 0,
    tls: 0,
    certificates: 0,
    signatures: 0,
    encryption: 0,
    hashing: 0
  };

  const rules = [
    {
      type: "RSA Usage",
      regex: /\bRSA\b|\brsa\b|\bRS256\b|\bRSA-OAEP\b/g,
      severity: "HIGH",
      category: "Quantum Vulnerable Cryptography",
      key: "rsa",
      recommendation:
        "Inventory RSA usage and plan migration to ML-KEM for key establishment or ML-DSA / SLH-DSA for signatures."
    },
    {
      type: "ECC Usage",
      regex: /\bECC\b|\bECDH\b|\bECDSA\b|\becdsa\b|\becdh\b/g,
      severity: "HIGH",
      category: "Quantum Vulnerable Cryptography",
      key: "ecc",
      recommendation:
        "Inventory elliptic-curve usage and plan migration toward post-quantum signature and key-establishment algorithms."
    },
    {
      type: "secp256k1 Usage",
      regex: /\bsecp256k1\b|\bk256\b/g,
      severity: "HIGH",
      category: "Blockchain Signature Exposure",
      key: "secp256k1",
      recommendation:
        "Review secp256k1 wallet/signature dependencies and prepare a post-quantum migration roadmap."
    },
    {
      type: "ECDSA Signature Usage",
      regex: /\bECDSA\b|\becrecover\b|\bsignature\b|\bpermit\b|\bEIP712\b/g,
      severity: "HIGH",
      category: "Signature Exposure",
      key: "ecdsa",
      recommendation:
        "Review ECDSA and EIP-712 signature flows for replay protection and long-term post-quantum migration."
    },
    {
      type: "SHA-1 Usage",
      regex: /\bSHA1\b|\bsha1\b/g,
      severity: "HIGH",
      category: "Weak Hashing",
      key: "sha1",
      recommendation:
        "Replace SHA-1 with stronger hashing algorithms and review legacy compatibility requirements."
    },
    {
      type: "SHA-256 Usage",
      regex: /\bSHA256\b|\bsha256\b|\bkeccak256\b/g,
      severity: "LOW",
      category: "Hashing Inventory",
      key: "sha256",
      recommendation:
        "Document SHA-256 or Keccak usage. Hash functions are less directly impacted by quantum attacks but should be inventoried."
    },
    {
      type: "TLS / HTTPS Usage",
      regex: /\bTLS\b|\bHTTPS\b|\bhttps:\/\//g,
      severity: "MEDIUM",
      category: "Transport Security Inventory",
      key: "tls",
      recommendation:
        "Inventory TLS endpoints and certificates. Track post-quantum TLS support as standards mature."
    },
    {
      type: "Certificate Usage",
      regex: /\bcertificate\b|\bcert\b|\bX509\b|\bx509\b|\bpem\b/g,
      severity: "MEDIUM",
      category: "Certificate Inventory",
      key: "certificates",
      recommendation:
        "Inventory certificate usage and prepare for future post-quantum certificate migration."
    },
    {
      type: "Encryption Usage",
      regex: /\bencrypt\b|\bdecrypt\b|\bcipher\b|\bcrypto\b/g,
      severity: "MEDIUM",
      category: "Cryptography Inventory",
      key: "encryption",
      recommendation:
        "Inventory encryption usage and identify where asymmetric cryptography is used."
    },
    {
      type: "Signature Usage",
      regex: /\bsign\b|\bverify\b|\bsigner\b|\bsignature\b/g,
      severity: "MEDIUM",
      category: "Signature Inventory",
      key: "signatures",
      recommendation:
        "Inventory signing and verification flows and classify whether they rely on RSA, ECDSA, or other schemes."
    }
  ];

  for (const file of files) {
    const fileName = file.name ?? "Unknown File";
    const content = file.content ?? "";
    const lines = content.split("\n");

    lines.forEach((line, index) => {
      if (isCommentOnlyLine(line)) return;

      for (const rule of rules) {
        const matches = line.match(rule.regex);

        if (!matches) continue;

        inventory[rule.key] += matches.length;

        findings.push({
          file: fileName,
          line: index + 1,
          type: rule.type,
          severity: rule.severity,
          category: rule.category,
          recommendation: rule.recommendation,
          occurrences: matches.length,
          context: {
            match: line.trim()
          }
        });
      }
    });
  }

  const highFindings = countSeverity(findings, "HIGH");
  const mediumFindings = countSeverity(findings, "MEDIUM");
  const lowFindings = countSeverity(findings, "LOW");

  const quantumRiskScore = Math.min(
    100,
    highFindings * 12 + mediumFindings * 5 + lowFindings * 1
  );

  const quantumReadinessScore = Math.max(0, 100 - quantumRiskScore);

  return {
    engine: "Quantum Readiness Engine",
    scannerVersion: "1.0.0",
    quantumReadinessScore,
    quantumRiskScore,
    quantumRiskLevel:
      quantumRiskScore >= 80
        ? "CRITICAL"
        : quantumRiskScore >= 60
        ? "HIGH"
        : quantumRiskScore >= 30
        ? "MEDIUM"
        : "LOW",
    highFindings,
    mediumFindings,
    lowFindings,
    totalQuantumFindings: findings.length,
    inventory,
    migrationReadiness:
      quantumRiskScore >= 60
        ? "Migration planning required"
        : quantumRiskScore >= 30
        ? "Review cryptographic inventory"
        : "Monitor and maintain crypto-agility",
    recommendedMigrationPath:
      highFindings > 0
        ? "Prioritize RSA, ECC, ECDSA, and secp256k1 inventory. Prepare migration roadmap toward ML-KEM, ML-DSA, and SLH-DSA where applicable."
        : "Maintain cryptographic inventory and monitor post-quantum standards adoption.",
    findings: findings.slice(0, 50)
  };
}

function countSeverity(findings = [], severity = "") {
  return findings.filter(finding => finding.severity === severity).length;
}

function isCommentOnlyLine(line = "") {
  const trimmed = line.trim();

  return (
    trimmed.startsWith("//") ||
    trimmed.startsWith("*") ||
    trimmed.startsWith("/*") ||
    trimmed.startsWith("*/")
  );
}
