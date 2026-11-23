import { execFile } from "node:child_process";
import { copyFile, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { prepareServerParityNativeAddon } from "./server-parity-native-addon.mjs";
import { readToolchains } from "./toolchains.mjs";

const execute = promisify(execFile);

export async function prepareServerParityPeers(root, runtimes) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "flowersec-parity-peers-"));
  const commands = {};
  try {
    if (runtimes.includes("go")) {
      const cwd = path.join(root, "flowersec-go");
      const command = path.join(directory, "go-peer");
      await execute("go", ["build", "-o", command, "./internal/cmd/server-parity-peer"], { cwd });
      commands.go = { cwd, command, arguments: [] };
    }
    if (runtimes.includes("rust")) {
      const { stdout } = await execute("rustup", ["run", readToolchains(root).rust.version, "cargo", "build", "--locked",
        "--manifest-path", "flowersec-rust/Cargo.toml", "--example", "server_parity_peer", "--message-format=json-render-diagnostics"],
      { cwd: root, maxBuffer: 16 * 1024 * 1024 });
      const artifact = stdout.trim().split("\n").map(line => JSON.parse(line)).find(entry =>
        entry.reason === "compiler-artifact" && entry.target.name === "server_parity_peer" && entry.target.kind.includes("example") && entry.executable);
      if (!artifact) throw new Error("Cargo did not produce the Rust server parity peer");
      const command = path.join(directory, "rust-peer");
      await copyFile(artifact.executable, command);
      commands.rust = { cwd: root, command, arguments: [] };
    }
    const node = runtimes.includes("node-typescript");
    if (node) commands["node-typescript"] = { cwd: path.join(root, "flowersec-ts"), command: process.execPath, arguments: ["--import", "tsx", "src/interop/serverParityPeer.ts"] };
    const addon = await prepareServerParityNativeAddon(root, node);
    return { commands, environment: addon.environment, cleanup: async () => {
      try { await addon.cleanup(); } finally { await rm(directory, { recursive: true, force: true }); }
    } };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
