export function securityCopilotEngine(findings = []) {
  return findings.map((finding) => {
    const guidance = getGuidanceForFinding(finding);

    return {
      file: finding.file,
      line: finding.line ?? "Unknown",
      type: finding.type,
      severity: finding.severity,
      category: finding.category ?? "Security Finding",
      confidence: finding.confidence ?? "MEDIUM",
      occurrences: finding.occurrences ?? 1,
      risk: guidance.risk,
      businessImpact: guidance.businessImpact,
      recommendation: guidance.recommendation,
      migrationPath: guidance.migrationPath,
      estimatedEffort: guidance.estimatedEffort,
      exampleFix: guidance.exampleFix,
      developerNote: guidance.developerNote
    };
  });
}

function getGuidanceForFinding(finding = {}) {
  const type = finding.type ?? "Unknown";

  const guidanceMap = {
    RSA: {
      risk: "RSA may require migration for long-term quantum resilience.",
      businessImpact:
        "Systems using RSA for encryption, signatures, or certificates may need future migration planning.",
      recommendation:
        "Inventory all RSA usage and determine whether it is used for encryption, signing, TLS, or certificates.",
      migrationPath: "RSA → ML-KEM for key establishment, ML-DSA or SLH-DSA for signatures",
      estimatedEffort: "Medium",
      exampleFix:
        "Create a cryptoProvider wrapper so RSA can be replaced without rewriting business logic.",
      developerNote:
        "Do not blindly replace production cryptography. First document where and why RSA is used."
    },

    ECDSA: {
      risk: "ECDSA signatures may become vulnerable in a future quantum threat model.",
      businessImpact:
        "Wallets, smart contracts, authentication systems, and certificates may require migration planning.",
      recommendation:
        "Identify signing flows and prepare a crypto-agile signature abstraction.",
      migrationPath: "ECDSA → ML-DSA or SLH-DSA",
      estimatedEffort: "Medium to High",
      exampleFix:
        "Route signing through a signatureProvider abstraction instead of calling ECDSA directly.",
      developerNote:
        "ECDSA is common in blockchain wallets, so migration must be planned carefully."
    },

    ECDH: {
      risk: "ECDH key exchange may require migration for quantum-safe key establishment.",
      businessImpact:
        "Encrypted communication channels may need future upgrade paths.",
      recommendation:
        "Move key exchange logic behind an abstraction layer and evaluate ML-KEM support.",
      migrationPath: "ECDH → ML-KEM",
      estimatedEffort: "Medium",
      exampleFix:
        "Use a keyExchangeProvider interface so algorithms can be swapped later.",
      developerNote:
        "Prioritize systems protecting long-lived sensitive data."
    },

    SHA1: {
      risk: "SHA1 is deprecated and should not be used for security-sensitive systems.",
      businessImpact:
        "Legacy hashing may weaken signatures, integrity checks, or compatibility-sensitive workflows.",
      recommendation:
        "Replace SHA1 with SHA-256 or SHA-3 where appropriate.",
      migrationPath: "SHA1 → SHA-256 or SHA-3",
      estimatedEffort: "Low to Medium",
      exampleFix:
        "Replace crypto.createHash('sha1') with crypto.createHash('sha256') where compatible.",
      developerNote:
        "Check compatibility before changing hashing in legacy systems."
    },

    MD5: {
      risk: "MD5 is deprecated and unsafe for security-sensitive use.",
      businessImpact:
        "MD5 can weaken integrity checks, password handling, or legacy authentication flows.",
      recommendation:
        "Replace MD5 with SHA-256, SHA-3, bcrypt, scrypt, or Argon2 depending on the use case.",
      migrationPath: "MD5 → SHA-256/SHA-3 or password-hashing algorithm",
      estimatedEffort: "Low to Medium",
      exampleFix:
        "Use SHA-256 for integrity checks and Argon2/bcrypt/scrypt for passwords.",
      developerNote:
        "Do not use general-purpose hashes for password storage."
    },

    "Private Key": {
      risk: "Private key material may be exposed in source code.",
      businessImpact:
        "Attackers may be able to access accounts, servers, wallets, or encrypted assets.",
      recommendation:
        "Remove the key immediately, rotate the credential, and review repository history.",
      migrationPath: "Hardcoded key → Secrets manager",
      estimatedEffort: "Immediate",
      exampleFix:
        "Move secrets into environment variables or a secrets manager.",
      developerNote:
        "Treat exposed private keys as compromised."
    },

    "Private Key Block": {
      risk: "A private key block appears to be present in scanned content.",
      businessImpact:
        "This may allow unauthorized signing, server access, wallet compromise, or data access.",
      recommendation:
        "Remove the private key, rotate it, and purge it from git history if needed.",
      migrationPath: "Source-controlled private key → Vault-managed secret",
      estimatedEffort: "Immediate",
      exampleFix:
        "Store private keys in AWS Secrets Manager, HashiCorp Vault, Doppler, 1Password, or GitHub Secrets.",
      developerNote:
        "This should be treated as a critical issue until proven otherwise."
    },

    "OpenAI Key": {
      risk: "Potential OpenAI API key detected.",
      businessImpact:
        "Exposed API keys can create unauthorized usage, billing risk, and data exposure.",
      recommendation:
        "Rotate the key and move it to an environment variable or secrets manager.",
      migrationPath: "Hardcoded API key → process.env.OPENAI_API_KEY",
      estimatedEffort: "Low",
      exampleFix:
        "Use process.env.OPENAI_API_KEY instead of hardcoding the key.",
      developerNote:
        "Never commit API keys to GitHub."
    },

    "AWS Access Key": {
      risk: "Potential AWS access key detected.",
      businessImpact:
        "AWS key exposure can create infrastructure takeover and financial risk.",
      recommendation:
        "Rotate the AWS key immediately and review IAM permissions.",
      migrationPath: "Static AWS key → IAM role or AWS Secrets Manager",
      estimatedEffort: "Immediate",
      exampleFix:
        "Use IAM roles, environment variables, or AWS Secrets Manager.",
      developerNote:
        "Review CloudTrail and IAM activity after exposure."
    },

    "GitHub Token": {
      risk: "Potential GitHub token detected.",
      businessImpact:
        "Exposed GitHub tokens can allow unauthorized code access, workflow abuse, or repository modification.",
      recommendation:
        "Revoke the token and generate a new one with least privilege.",
      migrationPath: "Hardcoded token → GitHub Actions secret",
      estimatedEffort: "Low",
      exampleFix:
        "Use GitHub Actions secrets instead of hardcoding tokens.",
      developerNote:
        "Review repository and organization access after exposure."
    },

    "API Key": {
      risk: "Potential API key detected.",
      businessImpact:
        "API key exposure can cause unauthorized usage, service abuse, or billing damage.",
      recommendation:
        "Move the key to environment variables or a secure secrets manager.",
      migrationPath: "Hardcoded API key → Environment variable or secrets manager",
      estimatedEffort: "Low",
      exampleFix:
        "Replace hardcoded API keys with process.env.API_KEY.",
      developerNote:
        "Rotate the key if it was committed."
    },

    "JWT Secret": {
      risk: "Potential JWT secret detected.",
      businessImpact:
        "Weak or exposed JWT secrets can allow token forgery.",
      recommendation:
        "Move JWT secrets into environment variables and rotate exposed secrets.",
      migrationPath: "Hardcoded JWT secret → process.env.JWT_SECRET",
      estimatedEffort: "Low",
      exampleFix:
        "Use process.env.JWT_SECRET instead of hardcoding secrets.",
      developerNote:
        "Review active sessions if the secret was exposed."
    },

    "Ethereum Private Key": {
      risk: "Potential Ethereum private key detected.",
      businessImpact:
        "If valid, this can lead to complete wallet compromise and asset loss.",
      recommendation:
        "Treat the key as compromised. Move funds to a new wallet and remove it from the repository.",
      migrationPath: "Hardcoded wallet key → Hardware wallet, vault, or environment secret",
      estimatedEffort: "Immediate",
      exampleFix:
        "Use a secure wallet provider or environment variable instead of hardcoding private keys.",
      developerNote:
        "Some 0x64-character values may be false positives. Verify carefully."
    },

    "Seed Phrase": {
      risk: "Possible wallet seed phrase reference detected.",
      businessImpact:
        "Seed phrase exposure can result in total wallet compromise.",
      recommendation:
        "Never store seed phrases in source code. Treat exposure as critical until disproven.",
      migrationPath: "Seed phrase in source → Secure offline storage",
      estimatedEffort: "Immediate",
      exampleFix:
        "Remove the phrase and move wallet access to a secure signing system.",
      developerNote:
        "Do not paste seed phrases into logs, code, config files, or tickets."
    }
  };

  return (
    guidanceMap[type] ?? {
      risk: "Security-sensitive pattern detected.",
      businessImpact:
        "This finding may represent a security or migration risk and should be reviewed.",
      recommendation:
        "Review this finding manually and determine whether remediation is required.",
      migrationPath: "Manual security review",
      estimatedEffort: "Unknown",
      exampleFix:
        "Document the risk and route the issue through security review.",
      developerNote:
        "Unknown finding type requires manual validation."
    }
  );
}
