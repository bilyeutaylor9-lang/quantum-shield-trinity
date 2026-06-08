export function htmlReportGenerator(report = {}) {
  const score = report.securityScoreReport ?? {};
  const executive = report.executiveReport ?? {};
  const dependency = report.dependencyRiskReport ?? {};
  const assessment = report.assessmentReport ?? {};
  const audit = report.smartContractAuditReport ?? {};
  const attackSurface = report.attackSurfaceReport ?? {};
  const simulation = report.exploitSimulationReport ?? {};
  const inventory = report.inventoryReport ?? {};

  const securityScore = score.securityScore ?? 0;
  const riskLevel = score.riskLevel ?? "UNKNOWN";
  const grade = score.grade ?? score.securityGrade ?? "N/A";
  const topPriority = score.topPriority ?? "Review high and critical findings.";

  const criticalFindings =
    score.findingCounts?.critical ??
    audit.criticalFindings ??
    assessment.criticalFindings?.length ??
    report.criticalFindings ??
    0;

  const highFindings =
    score.findingCounts?.high ??
    audit.highFindings ??
    report.highFindings ??
    0;

  const mediumFindings =
    score.findingCounts?.medium ??
    audit.mediumFindings ??
    report.mediumFindings ??
    0;

  const lowFindings =
    score.findingCounts?.low ??
    audit.lowFindings ??
    report.lowFindings ??
    0;

  const scannedFiles =
    executive.keyMetrics?.scannedFiles ??
    report.scannedFiles ??
    report.repositoryReport?.scannedFiles ??
    0;

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>Quantum Shield Trinity Report</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #0f172a;
      color: #e5e7eb;
      margin: 0;
      padding: 32px;
    }
    .container {
      max-width: 1100px;
      margin: auto;
    }
    .header {
      padding: 28px;
      border-radius: 18px;
      background: linear-gradient(135deg, #1e293b, #111827);
      border: 1px solid #334155;
      margin-bottom: 24px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 34px;
    }
    .subtitle {
      color: #94a3b8;
      font-size: 16px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .card,
    .section {
      background: #111827;
      border: 1px solid #334155;
      border-radius: 16px;
      padding: 22px;
      margin-bottom: 20px;
    }
    .label {
      color: #94a3b8;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: .08em;
    }
    .value {
      font-size: 30px;
      font-weight: bold;
      margin-top: 8px;
    }
    .risk-low { color: #22c55e; }
    .risk-medium { color: #f59e0b; }
    .risk-high { color: #fb7185; }
    .risk-critical { color: #ef4444; }
    h2 {
      margin-top: 0;
      color: #f8fafc;
    }
    h3 {
      color: #93c5fd;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
    }
    th, td {
      border-bottom: 1px solid #334155;
      padding: 10px;
      text-align: left;
      vertical-align: top;
    }
    th {
      color: #93c5fd;
    }
    .button {
      display: inline-block;
      padding: 14px 20px;
      background: #2563eb;
      color: #ffffff;
      text-decoration: none;
      border-radius: 10px;
      font-weight: bold;
      margin-top: 12px;
    }
    .footer {
      color: #64748b;
      font-size: 13px;
      margin-top: 24px;
      text-align: center;
    }
  </style>
</head>

<body>
  <div class="container">
    <div class="header">
      <h1>Quantum Shield Trinity</h1>
      <div class="subtitle">
        Security intelligence for smart contracts, dependencies, attack surfaces, and quantum exposure.
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="label">Security Score</div>
        <div class="value">${escapeHtml(securityScore)}/100</div>
      </div>

      <div class="card">
        <div class="label">Risk Level</div>
        <div class="value ${riskClass(riskLevel)}">${escapeHtml(riskLevel)}</div>
      </div>

      <div class="card">
        <div class="label">Grade</div>
        <div class="value">${escapeHtml(grade)}</div>
      </div>

      <div class="card">
        <div class="label">Version</div>
        <div class="value">${escapeHtml(report.version ?? "N/A")}</div>
      </div>
    </div>

    <div class="section">
      <h2>Executive Summary</h2>

      <table>
        <tr>
          <th>Metric</th>
          <th>Result</th>
        </tr>
        <tr>
          <td>Files Scanned</td>
          <td>${escapeHtml(scannedFiles)}</td>
        </tr>
        <tr>
          <td>Critical Findings</td>
          <td class="risk-critical">${escapeHtml(criticalFindings)}</td>
        </tr>
        <tr>
          <td>High Findings</td>
          <td class="risk-high">${escapeHtml(highFindings)}</td>
        </tr>
        <tr>
          <td>Medium Findings</td>
          <td class="risk-medium">${escapeHtml(mediumFindings)}</td>
        </tr>
        <tr>
          <td>Low Findings</td>
          <td class="risk-low">${escapeHtml(lowFindings)}</td>
        </tr>
      </table>

      <h3>Top Priority</h3>
      <p>${escapeHtml(topPriority)}</p>
    </div>

    <div class="section">
      <h2>Smart Contract Audit</h2>
      ${renderSmartContractTable(audit)}
    </div>

    <div class="section">
      <h2>Attack Surface Intelligence</h2>
      ${renderSimpleMetricsTable({
        "Risk Level": attackSurface.attackSurfaceRiskLevel ?? "N/A",
        "Attack Surface Score": `${attackSurface.attackSurfaceScore ?? "N/A"}/100`,
        "Total Attack Findings": attackSurface.totalAttackFindings ?? 0,
        "Critical Attack Paths": attackSurface.criticalAttackPaths ?? 0,
        "High Attack Paths": attackSurface.highAttackPaths ?? 0,
        "Medium Attack Paths": attackSurface.mediumAttackPaths ?? 0
      })}
    </div>

    <div class="section">
      <h2>Exploit Simulation</h2>
      ${renderSimpleMetricsTable({
        "Simulation Risk Level": simulation.simulationRiskLevel ?? "N/A",
        "Simulation Score": `${simulation.simulationScore ?? "N/A"}/100`,
        "Total Simulations": simulation.totalSimulations ?? 0,
        "Critical Simulations": simulation.criticalSimulations ?? 0,
        "High Simulations": simulation.highSimulations ?? 0
      })}
    </div>

    <div class="section">
      <h2>Dependency Risk</h2>
      ${renderDependencyTable(dependency)}
    </div>

    <div class="section">
      <h2>Quantum / Crypto Inventory</h2>
      ${renderSimpleMetricsTable({
        "Inventory Risk": inventory.riskLevel ?? inventory.inventoryRiskLevel ?? "N/A",
        "Detected Items": inventory.detectedItems?.length ?? inventory.totalItems ?? 0,
        "Quantum Exposure": inventory.quantumExposure ?? "Review Required"
      })}
    </div>

    <div class="section">
      <h2>Unlock the Full Quantum Shield Trinity Report</h2>

      <p>
        The public dashboard only displays a limited security summary.
        Upgrade to access the complete security intelligence package.
      </p>

      <table>
        <tr>
          <th>Feature</th>
          <th>Public</th>
          <th>Premium</th>
        </tr>
        <tr>
          <td>Security Score</td>
          <td>✓</td>
          <td>✓</td>
        </tr>
        <tr>
          <td>Risk Level</td>
          <td>✓</td>
          <td>✓</td>
        </tr>
        <tr>
          <td>Top Findings</td>
          <td>✓</td>
          <td>✓</td>
        </tr>
        <tr>
          <td>Full HTML Report</td>
          <td>✗</td>
          <td>✓</td>
        </tr>
        <tr>
          <td>SARIF Export</td>
          <td>✗</td>
          <td>✓</td>
        </tr>
        <tr>
          <td>Executive Report</td>
          <td>✗</td>
          <td>✓</td>
        </tr>
        <tr>
          <td>Exploit Simulation Analysis</td>
          <td>✗</td>
          <td>✓</td>
        </tr>
        <tr>
          <td>Dependency Intelligence</td>
          <td>✗</td>
          <td>✓</td>
        </tr>
        <tr>
          <td>Quantum Migration Guidance</td>
          <td>✗</td>
          <td>✓</td>
        </tr>
        <tr>
          <td>AI Remediation Recommendations</td>
          <td>✗</td>
          <td>✓</td>
        </tr>
      </table>

      <h3>Professional Security Analysis</h3>

      <p>
        Receive a complete security assessment including remediation guidance,
        attack-path analysis, smart contract findings, dependency risk analysis,
        quantum readiness evaluation, SARIF exports, and executive-ready reporting.
      </p>

      <p><strong>Coming Soon</strong></p>

      <p>Premium Reports • Enterprise Audits • Security Consulting</p>

      <a class="button" href="https://github.com/bilyeutaylor9-lang/quantum-shield-trinity">
        View Quantum Shield Trinity on GitHub
      </a>
    </div>

    <div class="footer">
      Generated by Quantum Shield Trinity
    </div>
  </div>
</body>
</html>`;
}

function renderSmartContractTable(audit = {}) {
  const findings = audit.topAuditFindings ?? audit.auditFindings ?? [];

  if (!findings.length) {
    return "<p>No smart contract findings detected.</p>";
  }

  const rows = findings
    .slice(0, 12)
    .map(
      finding => `<tr>
        <td>${escapeHtml(finding.severity)}</td>
        <td>${escapeHtml(finding.type)}</td>
        <td>${escapeHtml(finding.file)}</td>
        <td>${escapeHtml(finding.line)}</td>
        <td>${escapeHtml(finding.recommendation)}</td>
      </tr>`
    )
    .join("");

  return `<table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Finding</th>
        <th>File</th>
        <th>Line</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderDependencyTable(dependency = {}) {
  const findings = dependency.findings ?? dependency.dependencyFindings ?? [];

  if (!findings.length) {
    return "<p>No dependency findings detected.</p>";
  }

  const rows = findings
    .slice(0, 12)
    .map(
      finding => `<tr>
        <td>${escapeHtml(finding.dependency ?? "N/A")}</td>
        <td>${escapeHtml(finding.version ?? "N/A")}</td>
        <td>${escapeHtml(finding.severity ?? "N/A")}</td>
        <td>${escapeHtml(finding.category ?? finding.risk ?? "N/A")}</td>
        <td>${escapeHtml(finding.recommendation ?? "Review dependency risk.")}</td>
      </tr>`
    )
    .join("");

  return `<table>
    <thead>
      <tr>
        <th>Dependency</th>
        <th>Version</th>
        <th>Severity</th>
        <th>Category</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderSimpleMetricsTable(metrics = {}) {
  const rows = Object.entries(metrics)
    .map(
      ([label, value]) => `<tr>
        <td>${escapeHtml(label)}</td>
        <td>${escapeHtml(value)}</td>
      </tr>`
    )
    .join("");

  return `<table>
    <tbody>${rows}</tbody>
  </table>`;
}

function riskClass(riskLevel = "") {
  const normalized = String(riskLevel).toLowerCase();

  if (normalized === "low") return "risk-low";
  if (normalized === "medium") return "risk-medium";
  if (normalized === "high") return "risk-high";
  if (normalized === "critical") return "risk-critical";

  return "";
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
