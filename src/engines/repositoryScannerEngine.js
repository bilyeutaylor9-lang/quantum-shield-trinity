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
      type: "Private Key Block",
      regex: /BEGIN.*PRIVATE KEY/g,
      severity: "CRITICAL"
    },
    {
      type: "OpenAI Key",
      regex: /sk-[A-Za-z0-9]{20,}/g,
      severity: "CRITICAL"
    },
    {
      type: "AWS Access Key",
      regex: /AKIA[0-9A-Z]{16}/g,
      severity: "CRITICAL"
    },
    {
      type: "GitHub Token",
      regex: /ghp_[A-Za-z0-9]{20,}/g,
      severity: "CRITICAL"
    },
    {
      type: "API Key",
      regex: /api[_-]?key/gi,
      severity: "HIGH"
    },
    {
      type: "JWT Secret",
      regex: /jwt.*secret/gi,
      severity: "HIGH"
    }
  ];

  for (const file of files) {
    const fileName = file.name ?? "Unknown File";
    const content = file.content ?? "";
    const lines = content.split("\n");

    for (const pattern of patterns) {
      lines.forEach((line, index) => {
        const matches = line.match(pattern.regex);

        if (matches) {
          findings.push({
            file: fileName,
            line: index + 1,
            type: pattern.type,
            severity: pattern.severity,
            occurrences: matches.length
          });
        }
      });
    }
  }

  const criticalFindings = findings.filter(
    finding => finding.severity === "CRITICAL"
  ).length;

  const highFindings = findings.filter(
    finding => finding.severity === "HIGH"
  ).length;

  const mediumFindings = findings.filter(
    finding => finding.severity === "MEDIUM"
  ).length;

  const score = Math.min(
    100,
    criticalFindings * 40 +
      highFindings * 15 +
      mediumFindings * 8
  );

  return {
    engine: "Repository Scanner Engine",
    scannedFiles: files.length,
    findings,
    criticalFindings,
    highFindings,
    mediumFindings,
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
