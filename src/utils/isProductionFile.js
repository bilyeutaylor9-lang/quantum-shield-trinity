export function isProductionFile(fileName = "") {
  const normalized = fileName.toLowerCase();

  const excludedPaths = [
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
    ".github/"
  ];

  return !excludedPaths.some(path => normalized.includes(path));
}
