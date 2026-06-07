export function cryptoInventoryEngine(codeSample = "") {
  const vulnerableAlgorithms = [];

  if (codeSample.includes("RSA")) {
    vulnerableAlgorithms.push("RSA");
  }

  if (codeSample.includes("ECDSA")) {
    vulnerableAlgorithms.push("ECDSA");
  }

  if (codeSample.includes("ECDH")) {
    vulnerableAlgorithms.push("ECDH");
  }

  if (codeSample.includes("SHA1")) {
    vulnerableAlgorithms.push("SHA1");
  }

  const score = vulnerableAlgorithms.length * 25;

  return {
    engine: "Crypto Inventory Engine",
    findings: vulnerableAlgorithms.length,
    vulnerableAlgorithms,
    scannedFiles: 1,
    score
  };
}
