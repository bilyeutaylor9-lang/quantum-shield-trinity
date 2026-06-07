import { repositoryScannerEngine } from "../engines/repositoryScannerEngine.js";

const sampleFiles = [
  {
    name: "wallet.js",
    content: `
      const algorithm = "ECDSA";
      const API_KEY = "demo-api-key";
    `
  },
  {
    name: "server.js",
    content: `
      const encryption = "RSA";
      const legacyHash = "SHA1";
    `
  },
  {
    name: "secret.pem",
    content: `
      -----BEGIN PRIVATE KEY-----
      demo-private-key
      -----END PRIVATE KEY-----
    `
  }
];

const report = repositoryScannerEngine(sampleFiles);

console.log(JSON.stringify(report, null, 2));
