export const QUANTUM_RULES = [
  {
    id: "RSA",
    type: "RSA",
    regex: /\bRSA\b|createPrivateKey|createPublicKey|privateEncrypt|publicDecrypt/g,
    severity: "HIGH",
    category: "Quantum Vulnerable Crypto",
    description: "RSA usage detected. RSA may require migration for post-quantum resilience.",
    recommendation: "Inventory RSA usage and plan migration toward ML-KEM for key establishment and ML-DSA or SLH-DSA for signatures."
  },
  {
    id: "ECDSA",
    type: "ECDSA",
    regex: /\bECDSA\b|secp256k1|elliptic|ethers\.Wallet|signMessage|signTypedData/g,
    severity: "HIGH",
    category: "Quantum Vulnerable Signatures",
    description: "ECDSA or secp256k1-style signing detected.",
    recommendation: "Identify signing flows and prepare crypto-agile migration toward ML-DSA or SLH-DSA."
  },
  {
    id: "ECDH",
    type: "ECDH",
    regex: /\bECDH\b|createECDH|deriveKey|DiffieHellman|createDiffieHellman/g,
    severity: "HIGH",
    category: "Quantum Vulnerable Key Exchange",
    description: "ECDH or Diffie-Hellman key exchange detected.",
    recommendation: "Prepare migration toward ML-KEM-based key establishment."
  },
  {
    id: "SHA1",
    type: "SHA1",
    regex: /\bSHA1\b|\bsha1\b|createHash\(["']sha1["']\)/g,
    severity: "MEDIUM",
    category: "Deprecated Hashing",
    description: "SHA1 usage detected.",
    recommendation: "Replace SHA1 with SHA-256 or SHA-3 where appropriate."
  },
  {
    id: "MD5",
    type: "MD5",
    regex: /\bMD5\b|\bmd5\b|createHash\(["']md5["']\)/g,
    severity: "MEDIUM",
    category: "Deprecated Hashing",
    description: "MD5 usage detected.",
    recommendation: "Replace MD5 with SHA-256, SHA-3, or a modern password hashing algorithm where appropriate."
  },
  {
    id: "PRIVATE_KEY_BLOCK",
    type: "Private Key Block",
    regex: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    severity: "CRITICAL",
    category: "Secret Exposure",
    description: "Private key block detected in source code.",
    recommendation: "Remove immediately, rotate the key, and review git history."
  },
  {
    id: "OPENAI_KEY",
    type: "OpenAI Key",
    regex: /sk-[A-Za-z0-9_-]{20,}/g,
    severity: "CRITICAL",
    category: "Secret Exposure",
    description: "Potential OpenAI API key detected.",
    recommendation: "Rotate the key and move it to environment variables or a secrets manager."
  },
  {
    id: "GITHUB_TOKEN",
    type: "GitHub Token",
    regex: /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/g,
    severity: "CRITICAL",
    category: "Secret Exposure",
    description: "Potential GitHub token detected.",
    recommendation: "Revoke the token and use GitHub Actions secrets or a secure vault."
  },
  {
    id: "AWS_ACCESS_KEY",
    type: "AWS Access Key",
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: "CRITICAL",
    category: "Secret Exposure",
    description: "Potential AWS access key detected.",
    recommendation: "Rotate the key immediately and review IAM permissions."
  },
  {
    id: "JWT_SECRET",
    type: "JWT Secret",
    regex: /jwt[_-]?secret|JWT_SECRET|tokenSecret|signingSecret/gi,
    severity: "HIGH",
    category: "Authentication Risk",
    description: "JWT secret or signing secret reference detected.",
    recommendation: "Ensure secrets are stored in environment variables or a secure secrets manager."
  },
  {
    id: "HARDCODED_PASSWORD",
    type: "Hardcoded Password",
    regex: /password\s*[:=]\s*["'][^"']{6,}["']/gi,
    severity: "HIGH",
    category: "Secret Exposure",
    description: "Possible hardcoded password detected.",
    recommendation: "Remove hardcoded passwords and rotate affected credentials."
  },
  {
    id: "ENV_SECRET",
    type: "Environment Secret",
    regex: /(SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*["']?[^"'\n]{8,}/gi,
    severity: "HIGH",
    category: "Secret Exposure",
    description: "Potential secret value detected.",
    recommendation: "Move secrets into protected environment configuration or a vault."
  },
  {
    id: "ETH_PRIVATE_KEY",
    type: "Ethereum Private Key",
    regex: /0x[a-fA-F0-9]{64}/g,
    severity: "CRITICAL",
    category: "Wallet Secret Exposure",
    description: "Potential Ethereum private key detected.",
    recommendation: "Treat as compromised, move funds, and rotate wallet credentials."
  },
  {
    id: "MNEMONIC_PHRASE",
    type: "Seed Phrase",
    regex: /(seed phrase|mnemonic|recovery phrase).{0,40}/gi,
    severity: "CRITICAL",
    category: "Wallet Secret Exposure",
    description: "Possible wallet seed phrase reference detected.",
    recommendation: "Never store seed phrases in source code. Treat exposure as critical."
  },
  {
    id: "TLS_WEAK_VERSION",
    type: "Weak TLS Version",
    regex: /TLSv1\.0|TLSv1\.1|SSLv2|SSLv3/g,
    severity: "HIGH",
    category: "Transport Security",
    description: "Weak TLS or SSL version detected.",
    recommendation: "Disable SSL and old TLS versions. Require TLS 1.2+ or TLS 1.3."
  },
  {
    id: "INSECURE_RANDOM",
    type: "Insecure Randomness",
    regex: /Math\.random\(|randomBytes\(4\)|randomBytes\(8\)/g,
    severity: "MEDIUM",
    category: "Cryptographic Weakness",
    description: "Potential insecure randomness detected.",
    recommendation: "Use cryptographically secure randomness for secrets, tokens, and keys."
  },
  {
    id: "INSECURE_HTTP",
    type: "Insecure HTTP",
    regex: /http:\/\/(?!localhost|127\.0\.0\.1)/g,
    severity: "MEDIUM",
    category: "Transport Security",
    description: "Non-HTTPS URL detected.",
    recommendation: "Use HTTPS for production systems."
  }
];
