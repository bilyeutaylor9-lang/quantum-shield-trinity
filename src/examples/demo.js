import { quantumShieldTrinity } from "../index.js";

const wallet = {
  address: "0x123456789",
  transactionCount: 22,
  reusedAddress: true,
  signedMessages: 5
};

const codeSample = `
  RSA
  ECDSA
  SHA1
`;

const report = quantumShieldTrinity(wallet, codeSample);

console.log(JSON.stringify(report, null, 2));
