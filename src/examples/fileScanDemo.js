import { fileScanner } from "../scanners/fileScanner.js";
import { repositoryScannerEngine } from "../engines/repositoryScannerEngine.js";

const scanResult = fileScanner("src");

const report = repositoryScannerEngine(scanResult.files);

console.log(JSON.stringify(report, null, 2));
