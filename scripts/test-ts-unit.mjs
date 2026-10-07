import path from "node:path";
import { fileURLToPath } from "node:url";
import { runVitestWithNativeAddon } from "./server-parity-native-addon.mjs";

// SQLite unit paths use the same installed native admission extension as the
// published SDK. The existing runner owns build, staging and physical cleanup.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cancellation = new AbortController();
const interrupt = () => cancellation.abort(new Error("TypeScript unit gate received SIGINT"));
const terminate = () => cancellation.abort(new Error("TypeScript unit gate received SIGTERM"));
process.on("SIGINT", interrupt); process.on("SIGTERM", terminate);
try {
  // Match the coverage lane's bounded encryption workers when other SDKs run.
  await runVitestWithNativeAddon(root, ["run", "--maxWorkers=2", "--exclude", "src/**/*.integration.test.ts", ...process.argv.slice(2)], cancellation.signal);
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  process.removeListener("SIGINT", interrupt); process.removeListener("SIGTERM", terminate);
}
