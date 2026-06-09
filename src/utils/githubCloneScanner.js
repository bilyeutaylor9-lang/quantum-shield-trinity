import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";

export function isGitHubUrl(input = "") {
  return /^https:\/\/github\.com\/[^/\s]+\/[^/\s]+\/?$/.test(input.trim());
}

export function cloneGitHubRepo(repoUrl, options = {}) {
  const {
    depth = 1,
    singleBranch = true,
    blobless = true
  } = options;

  const safeName = repoUrl
    .replace("https://github.com/", "")
    .replace(/[^a-zA-Z0-9-_]/g, "-");

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "qst-scan-"));
  const targetPath = path.join(tempRoot, safeName);

  console.log(`Cloning GitHub repository: ${repoUrl}`);
  console.log(`Temporary scan path: ${targetPath}`);
  console.log(
    `Clone optimization: depth=${depth}, singleBranch=${singleBranch}, blobless=${blobless}`
  );
  console.log("");

  const cloneArgs = ["clone"];

  if (depth && Number(depth) > 0) {
    cloneArgs.push("--depth", String(depth));
  }

  if (singleBranch) {
    cloneArgs.push("--single-branch");
  }

  if (blobless) {
    cloneArgs.push("--filter=blob:none");
  }

  cloneArgs.push(repoUrl, targetPath);

  execFileSync("git", cloneArgs, {
    stdio: "inherit"
  });

  return {
    tempRoot,
    targetPath,
    repoUrl,
    cloneArgs
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
