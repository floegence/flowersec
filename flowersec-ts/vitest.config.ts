import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    coverage: {
      provider: "v8",
      reporter: ["text-summary", "json-summary"],
      thresholds: {
        lines: 76,
        functions: 77,
        statements: 72,
        branches: 63
      }
    }
  }
});
