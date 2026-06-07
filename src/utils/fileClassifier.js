export function classifyFile(fileName = "") {
  const file = fileName.toLowerCase();

  if (
    file.endsWith(".sol")
  ) {
    return "SMART_CONTRACT";
  }

  if (
    file.endsWith(".js") ||
    file.endsWith(".ts")
  ) {
    return "APPLICATION_CODE";
  }

  if (
    file.endsWith(".env")
  ) {
    return "SECRETS";
  }

  if (
    file.endsWith(".md") ||
    file.includes("readme") ||
    file.includes("whitepaper")
  ) {
    return "DOCUMENTATION";
  }

  return "OTHER";
}
