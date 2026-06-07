export const QUANTUM_RULES = [
  {
    id: "RSA",
    severity: "HIGH",
    description: "RSA may require post-quantum migration."
  },
  {
    id: "ECDSA",
    severity: "HIGH",
    description: "ECDSA may require post-quantum migration."
  },
  {
    id: "ECDH",
    severity: "HIGH",
    description: "ECDH may require post-quantum migration."
  },
  {
    id: "SHA1",
    severity: "MEDIUM",
    description: "SHA1 is deprecated."
  },
  {
    id: "PRIVATE KEY",
    severity: "CRITICAL",
    description: "Private key material detected."
  },
  {
    id: "API_KEY",
    severity: "HIGH",
    description: "Potential API key detected."
  }
];
