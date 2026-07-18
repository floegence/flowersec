import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    exclude: [...configDefaults.exclude, "browser-e2e/**"],
    coverage: {
      provider: "v8",
      reporter: ["text-summary", "json-summary"],
      thresholds: {
        lines: 82,
        functions: 82,
        statements: 77,
        branches: 68
      }
    }
  }
});
