import { fileScanner } from "./scanners/fileScanner.js";
import { repositoryScannerEngine } from "./engines/repositoryScannerEngine.js";

const targetDirectory = process.argv[2] ?? "src";

console.log("Quantum Shield Trinity");
console.log("----------------------");
console.log(`Scanning directory: ${targetDirectory}`);

const scanResult = fileScanner(targetDirectory);

const report = repositoryScannerEngine(scanResult.files);

console.log(JSON.stringify(report, null, 2));
