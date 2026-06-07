import { quantumShieldTrinity } from "../index.js";

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
