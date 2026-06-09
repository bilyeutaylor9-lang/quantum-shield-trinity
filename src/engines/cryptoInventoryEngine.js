export function cryptoInventoryEngine(files = []) {
  const assets = [];
  const inventory = {
    rsa: 0,
    ecc: 0,
    ecdsa: 0,
    ed25519: 0,
    secp256k1: 0,
    aes: 0,
    sha1: 0,
    sha256: 0,
    sha512: 0,
    keccak256: 0,
    hmac: 0,
    jwt: 0,
    privateKeys: 0,
    publicKeys: 0,
    certificates: 0,
    wallets: 0,
    signatures: 0,
    encryption: 0,
    hashing: 0
  };

  const rules = [
    {
      type: "RSA Cryptography",
      key: "rsa",
      regex: /\bRSA\b|\brsa\b|\bRS256\b|\bRSA-OAEP\b|\bRSA-PSS\b/g,
      severity: "HIGH",
      category: "Asymmetric Cryptography",
      quantumExposure: "HIGH",
      recommendation:
        "Inventory RSA usage and plan migration toward ML-KEM for key establishment or ML-DSA / SLH-DSA for signatures."
    },
    {
      type: "ECC Cryptography",
      key: "ecc",
      regex: /\bECC\b|\bECDH\b|\becdh\b|\belliptic\b|\bEllipticCurve\b/g,
      severity: "HIGH",
      category: "Asymmetric Cryptography",
      quantumExposure: "HIGH",
      recommendation:
        "Inventory elliptic-curve cryptography and prepare post-quantum migration planning."
    },
    {
      type: "ECDSA Signature Usage",
      key: "ecdsa",
      regex: /\bECDSA\b|\becdsa\b|\becrecover\b|\bEIP712\b|\bDOMAIN_SEPARATOR\b|\bpermit\s*\(/g,
      severity: "HIGH",
      category: "Digital Signatures",
      quantumExposure: "HIGH",
      recommendation:
        "Review ECDSA signing and verification flows. Prepare long-term migration to post-quantum or hybrid signatures."
    },
    {
      type: "secp256k1 Usage",
      key: "secp256k1",
      regex: /\bsecp256k1\b|\bk256\b|\bethereumjs-util\b|\beth_sign\b|\bpersonal_sign\b/g,
      severity: "HIGH",
      category: "Blockchain Signatures",
      quantumExposure: "HIGH",
      recommendation:
        "Review secp256k1 wallet and signature dependencies. Prepare a post-quantum migration roadmap."
    },
    {
      type: "Ed25519 Usage",
      key: "ed25519",
      regex: /\bEd25519\b|\bed25519\b|\bedDSA\b|\bEdDSA\b/g,
      severity: "MEDIUM",
      category: "Digital Signatures",
      quantumExposure: "HIGH",
      recommendation:
        "Inventory Ed25519 usage and evaluate long-term post-quantum signature alternatives."
    },
    {
      type: "AES Encryption",
      key: "aes",
      regex: /\bAES\b|\baes-\d+\b|\bAES-GCM\b|\bAES-CBC\b|\bcreateCipheriv\b|\bcreateDecipheriv\b/g,
      severity: "LOW",
      category: "Symmetric Encryption",
      quantumExposure: "LOW",
      recommendation:
        "Document AES usage, key sizes, modes, and key-management practices."
    },
    {
      type: "SHA-1 Hashing",
      key: "sha1",
      regex: /\bSHA1\b|\bSHA-1\b|\bsha1\b/g,
      severity: "HIGH",
      category: "Weak Hashing",
      quantumExposure: "MEDIUM",
      recommendation:
        "Replace SHA-1 with SHA-256, SHA-512, SHA-3, or another approved modern hash."
    },
    {
      type: "SHA-256 Hashing",
      key: "sha256",
      regex: /\bSHA256\b|\bSHA-256\b|\bsha256\b/g,
      severity: "LOW",
      category: "Hashing",
      quantumExposure: "LOW",
      recommendation:
        "Document SHA-256 usage. Hashing is less directly exposed to quantum attacks but should be inventoried."
    },
    {
      type: "SHA-512 Hashing",
      key: "sha512",
      regex: /\bSHA512\b|\bSHA-512\b|\bsha512\b/g,
      severity: "LOW",
      category: "Hashing",
      quantumExposure: "LOW",
      recommendation:
        "Document SHA-512 usage and confirm it is used appropriately."
    },
    {
      type: "Keccak256 Hashing",
      key: "keccak256",
      regex: /\bkeccak256\b|\bsolidityKeccak256\b|\butils\.keccak256\b/g,
      severity: "LOW",
      category: "Blockchain Hashing",
      quantumExposure: "LOW",
      recommendation:
        "Document Keccak usage in smart contracts, signing flows, and address derivation."
    },
    {
      type: "HMAC Usage",
      key: "hmac",
      regex: /\bHMAC\b|\bhmac\b|\bcreateHmac\b/g,
      severity: "LOW",
      category: "Message Authentication",
      quantumExposure: "LOW",
      recommendation:
        "Document HMAC usage and verify key-management practices."
    },
    {
      type: "JWT Usage",
      key: "jwt",
      regex: /\bJWT\b|\bjsonwebtoken\b|\bjose\b|\bRS256\b|\bES256\b|\bHS256\b/g,
      severity: "MEDIUM",
      category: "Token Signing",
      quantumExposure: "MEDIUM",
      recommendation:
        "Inventory JWT signing algorithms and avoid weak or misconfigured token verification."
    },
    {
      type: "Private Key Material",
      key: "privateKeys",
      regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|\bPRIVATE_KEY\b|\bprivateKey\b|\bmnemonic\b|\bseedPhrase\b/g,
      severity: "CRITICAL",
      category: "Key Exposure",
      quantumExposure: "HIGH",
      recommendation:
        "Remove private key material from source code. Rotate exposed keys and use a secure secret manager."
    },
    {
      type: "Public Key Material",
      key: "publicKeys",
      regex: /-----BEGIN (RSA |EC |OPENSSH )?PUBLIC KEY-----|\bPUBLIC_KEY\b|\bpublicKey\b/g,
      severity: "LOW",
      category: "Key Inventory",
      quantumExposure: "MEDIUM",
      recommendation:
        "Document public key usage and confirm associated private keys are protected."
    },
    {
      type: "Certificate Material",
      key: "certificates",
      regex: /-----BEGIN CERTIFICATE-----|\bX509\b|\bx509\b|\bcertificate\b|\bcert\b|\b\.pem\b|\b\.crt\b/g,
      severity: "MEDIUM",
      category: "Certificate Inventory",
      quantumExposure: "MEDIUM",
      recommendation:
        "Inventory certificate usage and prepare future post-quantum certificate migration planning."
    },
    {
      type: "Wallet Usage",
      key: "wallets",
      regex: /\bwallet\b|\bWallet\b|\bethers\.Wallet\b|\bnew Wallet\b|\bconnectWallet\b|\bMetaMask\b|\bprovider\.getSigner\b/g,
      severity: "MEDIUM",
      category: "Wallet Security",
      quantumExposure: "HIGH",
      recommendation:
        "Review wallet signing flows, key storage, and post-quantum migration exposure."
    },
    {
      type: "Signature Flow",
      key: "signatures",
      regex: /\bsignature\b|\bsignMessage\b|\bsignTypedData\b|\bverifyMessage\b|\bverifyTypedData\b|\bsigner\b|\bsign\(/g,
      severity: "MEDIUM",
      category: "Signature Inventory",
      quantumExposure: "HIGH",
      recommendation:
        "Inventory signing flows and identify whether RSA, ECDSA, EdDSA, or secp256k1 is used."
    },
    {
      type: "Encryption Flow",
      key: "encryption",
      regex: /\bencrypt\b|\bdecrypt\b|\bcipher\b|\bcrypto\b|\bsubtle\.encrypt\b|\bsubtle\.decrypt\b/g,
      severity: "MEDIUM",
      category: "Encryption Inventory",
      quantumExposure: "MEDIUM",
      recommendation:
        "Inventory encryption usage and identify where asymmetric cryptography or key exchange is used."
    },
    {
      type: "Hashing Flow",
      key: "hashing",
      regex: /\bhash\b|\bdigest\b|\bcreateHash\b|\bsubtle\.digest\b/g,
      severity: "LOW",
      category: "Hashing Inventory",
      quantumExposure: "LOW",
      recommendation:
        "Document hashing usage and confirm algorithms are appropriate for the security purpose."
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

        assets.push({
          file: fileName,
          line: index + 1,
          type: rule.type,
          category: rule.category,
          severity: rule.severity,
          quantumExposure: rule.quantumExposure,
          occurrences: matches.length,
          recommendation: rule.recommendation,
          context: {
            match: line.trim()
          }
        });
      }
    });
  }

  const criticalAssets = countSeverity(assets, "CRITICAL");
  const highAssets = countSeverity(assets, "HIGH");
  const mediumAssets = countSeverity(assets, "MEDIUM");
  const lowAssets = countSeverity(assets, "LOW");

  const quantumExposedAssets = assets.filter(asset =>
    ["HIGH", "MEDIUM"].includes(asset.quantumExposure)
  ).length;

  const inventoryRiskScore = Math.min(
    100,
    criticalAssets * 25 + highAssets * 12 + mediumAssets * 5 + lowAssets
  );

  const inventorySecurityScore = Math.max(0, 100 - inventoryRiskScore);

  return {
    engine: "Crypto Inventory Engine",
    scannerVersion: "1.0.0",
    totalCryptoAssets: assets.length,
    inventoryRiskScore,
    inventorySecurityScore,
    inventoryRiskLevel: getRiskLevel(inventoryRiskScore),
    criticalAssets,
    highAssets,
    mediumAssets,
    lowAssets,
    quantumExposedAssets,
    inventory,
    quantumExposureSummary: buildQuantumExposureSummary(inventory, quantumExposedAssets),
    recommendedActions: buildRecommendedActions(inventory, criticalAssets, highAssets),
    assets: assets.slice(0, 100)
  };
}

function countSeverity(items = [], severity = "") {
  return items.filter(item => item.severity === severity).length;
}

function getRiskLevel(score = 0) {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "MEDIUM";
  return "LOW";
}

function buildQuantumExposureSummary(inventory = {}, quantumExposedAssets = 0) {
  const exposed = [];

  if (inventory.rsa > 0) exposed.push("RSA");
  if (inventory.ecc > 0) exposed.push("ECC");
  if (inventory.ecdsa > 0) exposed.push("ECDSA");
  if (inventory.ed25519 > 0) exposed.push("Ed25519");
  if (inventory.secp256k1 > 0) exposed.push("secp256k1");
  if (inventory.wallets > 0) exposed.push("Wallet signing flows");
  if (inventory.signatures > 0) exposed.push("Signature flows");

  if (!exposed.length) {
    return "No major quantum-vulnerable cryptographic assets detected.";
  }

  return `${quantumExposedAssets} quantum-exposed cryptographic references detected: ${exposed.join(", ")}.`;
}

function buildRecommendedActions(inventory = {}, criticalAssets = 0, highAssets = 0) {
  const actions = [];

  if (criticalAssets > 0) {
    actions.push("Immediately remove private key material from source code and rotate exposed secrets.");
  }

  if (inventory.rsa > 0) {
    actions.push("Inventory RSA usage and classify whether it supports encryption, signing, TLS, or certificates.");
  }

  if (inventory.ecdsa > 0 || inventory.secp256k1 > 0 || inventory.ecc > 0) {
    actions.push("Build a post-quantum migration roadmap for ECC, ECDSA, and secp256k1 signature flows.");
  }

  if (inventory.sha1 > 0) {
    actions.push("Replace SHA-1 with SHA-256, SHA-512, SHA-3, or another approved modern hash.");
  }

  if (inventory.certificates > 0) {
    actions.push("Document certificate usage and track post-quantum certificate migration requirements.");
  }

  if (highAssets > 0) {
    actions.push("Prioritize high-risk cryptographic assets in remediation planning.");
  }

  if (!actions.length) {
    actions.push("Maintain cryptographic inventory and monitor post-quantum security standards.");
  }

  return actions;
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
