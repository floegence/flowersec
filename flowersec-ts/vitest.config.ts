import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    coverage: {
      provider: "v8",
      reporter: ["text-summary", "json-summary"],
      thresholds: {
        lines: 72,
        functions: 71,
        statements: 68,
        branches: 59
      }
    }
  }
});
