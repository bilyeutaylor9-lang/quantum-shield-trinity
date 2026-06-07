export function isProductionFile(fileName = "") {
  const normalized = fileName
    .replaceAll("\\", "/")
    .toLowerCase();

  const excludedPathParts = [
    "/test/",
    "/tests/",
    "/mock/",
    "/mocks/",
    "/example/",
    "/examples/",
    "/demo/",
    "/demos/",
    "/lib/",
    "/vendor/",
    "/node_modules/",
    "/forge-std/",
    "/openzeppelin/",
    "/src/engines/",
    "/src/rules/",
    "/src/reporters/",
    "/src/utils/",
    "readme.md"
  ];

  return !excludedPathParts.some(path =>
    normalized.includes(path)
  );
}
