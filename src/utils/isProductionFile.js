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
    "/reactive-lib/",
    "/.github/"
  ];

  const excludedFilePatterns = [
    ".t.sol",
    ".test.sol",
    ".spec.sol",
    "test.sol",
    "mock.sol",
    "fixture.sol"
  ];

  const isExcludedPath = excludedPathParts.some(part =>
    normalized.includes(part)
  );

  const isExcludedFile = excludedFilePatterns.some(pattern =>
    normalized.endsWith(pattern) || normalized.includes(pattern)
  );

  return !isExcludedPath && !isExcludedFile;
}
