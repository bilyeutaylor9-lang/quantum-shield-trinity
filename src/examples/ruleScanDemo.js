import { fileScanner } from "../scanners/fileScanner.js";
import { ruleBasedScanner } from "../scanners/ruleBasedScanner.js";

const files = fileScanner("src");

const report = ruleBasedScanner(files.files);

console.log(JSON.stringify(report, null, 2));
