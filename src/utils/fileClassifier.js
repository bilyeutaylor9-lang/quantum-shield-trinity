export function classifyFile(fileName = "") {
  const file = fileName.toLowerCase();

  if (
    file.includes("/test/") ||
    file.includes("/tests/") ||
    file.includes(".t.sol") ||
    file.includes("mock") ||
    file.includes("fixture")
  ) {
    return "TEST";
  }

  if (
    file.endsWith(".sol")
  ) {
    return "SMART_CONTRACT";
  }

  if (
    file.endsWith(".md") ||
    file.includes("readme") ||
    file.includes("whitepaper")
  ) {
    return "DOCUMENTATION";
  }

  if (
    file.endsWith(".env")
  ) {
    return "SECRETS";
  }

  return "OTHER";
}
