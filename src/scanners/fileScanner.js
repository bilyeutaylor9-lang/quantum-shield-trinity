import fs from "fs";
import path from "path";

const SUPPORTED_EXTENSIONS = [
  ".js",
  ".ts",
  ".jsx",
  ".tsx",
  ".json",
  ".sol",
  ".py",
  ".go",
  ".rs",
  ".env"
];

const IGNORED_FOLDERS = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "coverage"
];

export function fileScanner(targetDirectory = ".") {
  const files = [];

  function scanDirectory(directory) {
    const entries = fs.readdirSync(directory, {
      withFileTypes: true
    });

    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name);

      if (entry.isDirectory()) {
        if (!IGNORED_FOLDERS.includes(entry.name)) {
          scanDirectory(fullPath);
        }
        continue;
      }

      const extension = path.extname(entry.name);

      if (!SUPPORTED_EXTENSIONS.includes(extension)) {
        continue;
      }

      const content = fs.readFileSync(fullPath, "utf8");

      files.push({
        name: fullPath,
        content
      });
    }
  }

  scanDirectory(targetDirectory);

  return {
    scanner: "File Scanner",
    targetDirectory,
    scannedFiles: files.length,
    files
  };
}
