![Quantum Shield Trinity Scan](https://github.com/bilyeutaylor9-lang/quantum-shield-trinity/actions/workflows/scan.yml/badge.svg)

# Quantum Shield Trinity

Quantum Shield Trinity is a quantum risk intelligence platform designed to help users, developers, and organizations identify cryptographic exposure, assess quantum-related risk, and prepare migration strategies.

## Mission

Modern wallets, applications, APIs, and infrastructure depend on cryptographic systems that may become vulnerable as quantum computing advances.

Quantum Shield Trinity helps answer three critical questions:

1. Where are we exposed?
2. How serious is the risk?
3. What should we do next?

## Core Engines

### 1. Wallet Quantum Risk Engine
## Running Scans

### Scan a repository

```bash
npm run scan -- /path/to/repository
Analyzes wallet exposure based on:

- Transaction activity
- Address reuse
- Signed message activity
- Exposure scoring
- Wallet risk level

### 2. Crypto Inventory Engine

Scans code samples for vulnerable or migration-sensitive cryptographic patterns, including:

- RSA
- ECDSA
- ECDH
- SHA1

### 3. Migration Shield Engine

Generates migration recommendations based on wallet and cryptographic exposure.

### 4. Security Assessment Engine

Produces institutional-style quantum risk assessments including:

- Total risk score
- Risk level
- Critical findings
- Executive summary
- Recommended next steps

### 5. Quantum Exposure Forecast Engine

Forecasts future-facing quantum exposure, including:

- Q-Day exposure
- Harvest-now-decrypt-later risk
- Migration urgency
- Long-term business impact

### 6. Quantum Attack Simulation Engine

Models potential attack paths and business risk from quantum-related exposure.

## Central Risk Profile

Quantum Shield Trinity combines all engine outputs into one unified Quantum Risk Profile.

This profile is designed to support:

- Dashboards
- JSON exports
- Security reports
- Institutional reviews
- Future API integrations

## Example Use

```js
import { quantumShieldTrinity } from "./src/index.js";

const report = quantumShieldTrinity(
  {
    address: "0x123456789",
    transactionCount: 22,
    reusedAddress: true,
    signedMessages: 5
  },
  `
    RSA
    ECDSA
    SHA1
  `
);

console.log(JSON.stringify(report, null, 2));
