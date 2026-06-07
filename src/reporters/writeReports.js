import fs from "fs";

export function writeReports({
  htmlReport = "",
  exportReport = {},
  executiveReport = {},
  sarifReport = {}
} = {}) {
  fs.writeFileSync("report.html", htmlReport, "utf8");

  fs.writeFileSync(
    "report.json",
    JSON.stringify(exportReport, null, 2),
    "utf8"
  );

  fs.writeFileSync(
    "executive-report.json",
    JSON.stringify(executiveReport, null, 2),
    "utf8"
  );

  fs.writeFileSync(
    "report.sarif",
    JSON.stringify(sarifReport, null, 2),
    "utf8"
  );

  return {
    generatedFiles: [
      "report.html",
      "report.json",
      "executive-report.json",
      "report.sarif"
    ],
    generatedAt: new Date().toISOString()
  };
}
