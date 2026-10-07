import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolveRustTargetDirectory } from "./server-parity-native-addon.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const rustRoot = path.join(repositoryRoot, "flowersec-rust");
// make rust-cover-check first refreshes the profiles with cargo llvm-cov's
// normal test run. Continue in that same target so report merges real peers.
const targetDirectory = process.env.CARGO_LLVM_COV_TARGET_DIR
  ? path.resolve(repositoryRoot, process.env.CARGO_LLVM_COV_TARGET_DIR)
  : path.join(resolveRustTargetDirectory(repositoryRoot), "llvm-cov-target");
const reportEnvironment = { ...process.env, CARGO_LLVM_COV_TARGET_DIR: targetDirectory };
const shown = await run("cargo", ["llvm-cov", "show-env", "--sh"], {
  ...reportEnvironment, CARGO_TARGET_DIR: targetDirectory,
}, true);
const instrumentEnvironment = parseEnvironment(shown);
if (!(instrumentEnvironment.__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS ?? "").includes("instrument-coverage")
    || !instrumentEnvironment.RUSTC_WRAPPER
    || !path.isAbsolute(instrumentEnvironment.LLVM_PROFILE_FILE ?? "")) {
  throw new Error("cargo llvm-cov show-env did not supply its instrumented compiler and profile path");
}
instrumentEnvironment.CARGO_TARGET_DIR = targetDirectory;
// Only the instrumented Rust build and Rust peers receive these variables.
// Node's separate native addon remains in its own ordinary build directory.
await run("cargo", ["build", "--locked", "--all-features", "--example", "server_parity_peer"], {
  ...reportEnvironment, ...instrumentEnvironment,
});
const matrixEnvironment = { ...process.env };
for (const key of Object.keys(matrixEnvironment)) {
  if (key.startsWith("FLOWERSEC_PARITY_") || key.startsWith("__CARGO_LLVM_COV_")
      || key.startsWith("CARGO_LLVM_COV") || ["CARGO_TARGET_DIR", "LLVM_PROFILE_FILE", "RUSTC_WRAPPER"].includes(key)) {
    delete matrixEnvironment[key];
  }
}
matrixEnvironment.FLOWERSEC_PARITY_RUST_COVERAGE_ENV = JSON.stringify(instrumentEnvironment);
matrixEnvironment.FLOWERSEC_PARITY_RUST_PEER_READY = "1";
matrixEnvironment.FLOWERSEC_PARITY_RELAYS = "rust";
const workflows = [
  ["live4", { FLOWERSEC_PARITY_ACTIVATION_SOURCE: "live_authority", FLOWERSEC_PARITY_ENDPOINT_AS: "go", FLOWERSEC_PARITY_ENDPOINT_BS: "rust" }],
  ["pool4", { FLOWERSEC_PARITY_ACTIVATION_SOURCE: "preauthorized_pool", FLOWERSEC_PARITY_ENDPOINT_AS: "go", FLOWERSEC_PARITY_ENDPOINT_BS: "rust" }],
  ["registered-pool", { FLOWERSEC_PARITY_ACTIVATION_SOURCE: "preauthorized_pool", FLOWERSEC_PARITY_ENDPOINT_AS: "go", FLOWERSEC_PARITY_ENDPOINT_BS: "rust", FLOWERSEC_PARITY_CARRIERS: "websocket", FLOWERSEC_PARITY_REGISTERED_POOL: "1" }],
  ["registered-pool-reverse", { FLOWERSEC_PARITY_ACTIVATION_SOURCE: "preauthorized_pool", FLOWERSEC_PARITY_ENDPOINT_AS: "go", FLOWERSEC_PARITY_ENDPOINT_BS: "rust", FLOWERSEC_PARITY_CARRIERS: "raw-quic", FLOWERSEC_PARITY_REGISTERED_POOL: "1", FLOWERSEC_PARITY_CLIENT_LISTENER: "endpoint", FLOWERSEC_PARITY_SERVER_LISTENER: "relay" }],
  ["registered-live12", { FLOWERSEC_PARITY_ACTIVATION_SOURCE: "live_authority" }],
  ["pool-hop-capacity", { FLOWERSEC_PARITY_ACTIVATION_SOURCE: "preauthorized_pool", FLOWERSEC_PARITY_ENDPOINT_AS: "rust", FLOWERSEC_PARITY_ENDPOINT_BS: "rust", FLOWERSEC_PARITY_RELAYS: "go", FLOWERSEC_PARITY_CARRIERS: "raw-quic", FLOWERSEC_PARITY_HOP_CAPACITY_PROBE: "insufficient" }],
  ["pool-rust-node", { FLOWERSEC_PARITY_ACTIVATION_SOURCE: "preauthorized_pool", FLOWERSEC_PARITY_ENDPOINT_AS: "rust", FLOWERSEC_PARITY_ENDPOINT_BS: "node-typescript", FLOWERSEC_PARITY_CARRIERS: "websocket" }],
  ["pool-node-relay", { FLOWERSEC_PARITY_ACTIVATION_SOURCE: "preauthorized_pool", FLOWERSEC_PARITY_ENDPOINT_AS: "rust", FLOWERSEC_PARITY_ENDPOINT_BS: "go", FLOWERSEC_PARITY_RELAYS: "node-typescript", FLOWERSEC_PARITY_CARRIERS: "websocket" }],
  ["reverse-native-rust", { FLOWERSEC_PARITY_ACTIVATION_SOURCE: "live_authority", FLOWERSEC_PARITY_ENDPOINT_AS: "rust", FLOWERSEC_PARITY_ENDPOINT_BS: "node-typescript", FLOWERSEC_PARITY_CARRIERS: "raw-quic", FLOWERSEC_PARITY_CLIENT_LISTENER: "endpoint" }],
];
for (const carrier of ["websocket", "raw-quic"]) {
  workflows.push([`pool-go-${carrier}`, {
    FLOWERSEC_PARITY_ACTIVATION_SOURCE: "preauthorized_pool", FLOWERSEC_PARITY_ENDPOINT_AS: "rust", FLOWERSEC_PARITY_ENDPOINT_BS: "rust",
    FLOWERSEC_PARITY_RELAYS: "go", FLOWERSEC_PARITY_CARRIERS: carrier,
  }]);
  for (const [name, client, server] of [["a", "endpoint", "endpoint"], ["b", "relay", "relay"], ["ab", "endpoint", "relay"]]) {
    workflows.push([`reverse-${carrier}-${name}`, {
      FLOWERSEC_PARITY_ACTIVATION_SOURCE: "live_authority", FLOWERSEC_PARITY_ENDPOINT_AS: "go", FLOWERSEC_PARITY_ENDPOINT_BS: "rust",
      FLOWERSEC_PARITY_CARRIERS: carrier, FLOWERSEC_PARITY_CLIENT_LISTENER: client, FLOWERSEC_PARITY_SERVER_LISTENER: server,
    }]);
  }
}
for (const [name, environment] of workflows) {
  console.log(`Rust coverage: ${name}`);
  // The existing matrix verifies every successful Rust peer emitted a fresh,
  // nonempty process-specific profile before accepting its exit.
  await run(process.execPath, [path.join(repositoryRoot, "scripts/test-server-parity-tunnel.mjs")], {
    ...matrixEnvironment, ...environment,
  }, false, repositoryRoot);
}
for (const [client, server] of [["go", "rust"], ["rust", "go"]]) {
  console.log(`Rust coverage: direct ${client} to ${server}`);
  await run(process.execPath, [path.join(repositoryRoot, "scripts/test-server-parity-direct.mjs")], {
    ...matrixEnvironment, FLOWERSEC_PARITY_CLIENTS: client, FLOWERSEC_PARITY_SERVERS: server,
  }, false, repositoryRoot);
}
// The same public ProxyServer integration launches the prepared instrumented
// peer directly. Compilation variables never reach Node's native addon build.
const proxyPrefix = `proxy-${randomUUID()}-`, profileDirectory = path.dirname(instrumentEnvironment.LLVM_PROFILE_FILE);
console.log("Rust coverage: public ProxyServer");
await run(process.execPath, [path.join(repositoryRoot, "scripts/server-parity-native-addon.mjs"), "--vitest", "run",
  "src/interop/proxyServerMatrix.integration.test.ts", "-t", "against Rust ProxyServer"], {
  ...matrixEnvironment,
  FLOWERSEC_SERVER_PARITY_RUST_PEER_BINARY: path.join(targetDirectory, "debug", "examples", process.platform === "win32" ? "server_parity_peer.exe" : "server_parity_peer"),
  LLVM_PROFILE_FILE: path.join(profileDirectory, `${proxyPrefix}%p-%m.profraw`),
}, false, repositoryRoot);
const proxyProfiles = (await readdir(profileDirectory)).filter(name => name.startsWith(proxyPrefix) && name.endsWith(".profraw"));
if (proxyProfiles.length !== 1 || !(await stat(path.join(profileDirectory, proxyProfiles[0]))).size) {
  throw new Error("Rust ProxyServer exited without its fresh nonempty coverage profile");
}
// cargo-llvm-cov applies feature selection while building/running; its report
// subcommand reads the retained profiles and rejects --all-features on 0.8.x.
await run("cargo", ["llvm-cov", "report", "--fail-under-lines", "85"], reportEnvironment);

function parseEnvironment(output) {
  const environment = {};
  for (const line of output.split("\n")) {
    const match = /^export ([A-Za-z_][A-Za-z0-9_]*)=(.*)$/u.exec(line);
    if (match === null) continue;
    const [, key, value] = match;
    if (!(key.startsWith("__CARGO_LLVM_COV_") || key.startsWith("CARGO_LLVM_COV")
        || ["RUSTC_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "LLVM_PROFILE_FILE"].includes(key))) {
      throw new Error(`unexpected cargo llvm-cov environment key: ${key}`);
    }
    // show-env uses single-quoted shell strings or unquoted scalar values.
    // Decode data without evaluating shell commands or inherited environment.
    environment[key] = value.startsWith("'") && value.endsWith("'")
      ? value.slice(1, -1).replaceAll("'\\''", "'")
      : value;
  }
  return environment;
}

async function run(command, args, env, capture = false, cwd = rustRoot) {
  const child = spawn(command, args, { cwd, env, stdio: ["ignore", capture ? "pipe" : "inherit", "inherit"] });
  let output = "";
  if (capture) {
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", chunk => { output += chunk; });
  }
  const code = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => signal === null ? resolve(code) : reject(new Error(`${command} stopped by ${signal}`)));
  });
  if (code !== 0) throw new Error(`${command} ${args.join(" ")} failed with exit ${code}`);
  return output;
}
