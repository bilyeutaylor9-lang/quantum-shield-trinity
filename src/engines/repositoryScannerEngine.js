export function repositoryScannerEngine(files = []) {
  const findings = [];

  const patterns = [
    {
      type: "RSA",
      regex: /\bRSA\b/g,
      severity: "HIGH"
    },
    {
      type: "ECDSA",
      regex: /\bECDSA\b/g,
      severity: "HIGH"
    },
    {
      type: "ECDH",
      regex: /\bECDH\b/g,
      severity: "HIGH"
    },
    {
      type: "SHA1",
      regex: /\bSHA1\b/g,
      severity: "MEDIUM"
    },
    {
      type: "Private Key",
      regex: /PRIVATE KEY/g,
      severity: "CRITICAL"
    },
    {
      type: "API Key",
      regex: /api[_-]?key/gi,
      severity: "HIGH"
    }
  ];

  for (const file of files) {
    const fileName = file.name ?? "Unknown File";
    const content = file.content ?? "";

    for (const pattern of patterns) {
      const matches = content.match(pattern.regex);

      if (matches) {
        findings.push({
          file: fileName,
          type: pattern.type,
          severity: pattern.severity,
          occurrences: matches.length
        });
      }
    }
  }

  const criticalFindings = findings.filter(
    finding => finding.severity === "CRITICAL"
  ).length;

  const highFindings = findings.filter(
    finding => finding.severity === "HIGH"
  ).length;

  const score = Math.min(
    100,
    criticalFindings * 40 +
    highFindings * 15 +
    findings.length * 5
  );

  return {
    engine: "Repository Scanner Engine",
    scannedFiles: files.length,
    findings,
    criticalFindings,
    highFindings,
    score,
    repositoryRiskLevel:
      score >= 90
        ? "CRITICAL"
        : score >= 70
        ? "HIGH"
        : score >= 40
        ? "MEDIUM"
        : "LOW"
  };
}
