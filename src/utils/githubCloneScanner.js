import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";

export function isGitHubUrl(input = "") {
  return /^https:\/\/github\.com\/[^/\s]+\/[^/\s]+\/?$/.test(input.trim());
}

export function cloneGitHubRepo(repoUrl) {
  const safeName = repoUrl
    .replace("https://github.com/", "")
    .replace(/[^a-zA-Z0-9-_]/g, "-");

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "qst-scan-"));
  const targetPath = path.join(tempRoot, safeName);

  console.log(`Cloning GitHub repository: ${repoUrl}`);
  console.log(`Temporary scan path: ${targetPath}`);
  console.log("");

  execFileSync(
    "git",
    ["clone", "--depth", "1", repoUrl, targetPath],
    {
      stdio: "inherit"
    }
  );

  return {
    tempRoot,
    targetPath
  };
}

export function cleanupClonedRepo(tempRoot) {
  if (!tempRoot) return;

  try {
    fs.rmSync(tempRoot, {
      recursive: true,
      force: true
    });
  } catch {
    // Non-fatal cleanup failure.
  }
}
