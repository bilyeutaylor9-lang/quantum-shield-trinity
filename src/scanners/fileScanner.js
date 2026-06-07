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
  ".env",
  ".pem",
  ".yaml",
  ".yml",
  ".toml",
  ".config",
  ".conf",
  ".ini",
  ".sh",
  ".md",
  ".txt",
  ".lock"
];

const IMPORTANT_FILENAMES = [
  ".env",
  ".env.local",
  ".env.production",
  ".env.development",
  "Dockerfile",
  "docker-compose.yml",
  "package.json",
  "package-lock.json",
  "foundry.toml",
  "hardhat.config.js",
  "truffle-config.js",
  "remappings.txt"
];

const IGNORED_FOLDERS = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "coverage",
  "out",
  "cache"
];

const IGNORED_FILE_PATTERNS = [
  ".min.js"
];

function shouldIgnoreFile(filePath) {
  const normalizedPath = filePath.replaceAll("\\", "/").toLowerCase();

  return IGNORED_FILE_PATTERNS.some(pattern =>
    normalizedPath.includes(pattern)
  );
}

function shouldScanFile(filePath) {
  const fileName = path.basename(filePath);
  const extension = path.extname(fileName);

  return (
    SUPPORTED_EXTENSIONS.includes(extension) ||
    IMPORTANT_FILENAMES.includes(fileName)
  );
}

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

      if (shouldIgnoreFile(fullPath)) {
        continue;
      }

      if (!shouldScanFile(fullPath)) {
        continue;
      }

      try {
        const content = fs.readFileSync(fullPath, "utf8");

        files.push({
          name: fullPath,
          content
        });
      } catch {
        // Skip unreadable or binary files safely.
      }
    }
  }

  scanDirectory(targetDirectory);

  return {
    scanner: "Deep File Scanner",
    targetDirectory,
    scannedFiles: files.length,
    files
  };
}
