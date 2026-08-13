import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const platforms = Object.freeze({
  "darwin-arm64": Object.freeze({ package: "darwin-arm64", library: "libflowersec_node_native.dylib" }),
  "darwin-x64": Object.freeze({ package: "darwin-x64", library: "libflowersec_node_native.dylib" }),
  "linux-arm64": Object.freeze({ package: "linux-arm64-gnu", library: "libflowersec_node_native.so" }),
  "linux-x64": Object.freeze({ package: "linux-x64-gnu", library: "libflowersec_node_native.so" }),
});

export async function prepareServerParityNativeAddon(repositoryRoot, required) {
  if (!required) return Object.freeze({ environment: Object.freeze({}), cleanup: async () => {} });

  const platform = platforms[`${process.platform}-${process.arch}`];
  if (platform === undefined) throw new Error("server parity native addon is unavailable on this platform");

  await execFileAsync("rustup", [
    "run", "1.88.0", "cargo", "build", "--locked", "--manifest-path",
    path.join(repositoryRoot, "flowersec-node-native/Cargo.toml"),
  ], { cwd: repositoryRoot });

  const scratchRoot = path.join(repositoryRoot, ".flowersec");
  await mkdir(scratchRoot, { recursive: true });
  const stagingRoot = await mkdtemp(path.join(scratchRoot, "server-parity-native-"));
  try {
    const scopeRoot = path.join(stagingRoot, "node_modules/@floegence");
    const wrapperRoot = path.join(scopeRoot, "flowersec-node-native");
    const platformRoot = path.join(scopeRoot, `flowersec-node-native-${platform.package}`);
    await mkdir(wrapperRoot, { recursive: true });
    await mkdir(platformRoot, { recursive: true });
    await Promise.all([
      copyFile(path.join(repositoryRoot, "flowersec-node-native/index.js"), path.join(wrapperRoot, "index.js")),
      copyFile(path.join(repositoryRoot, "flowersec-node-native/package.json"), path.join(wrapperRoot, "package.json")),
      copyFile(
        path.join(repositoryRoot, `flowersec-node-native/npm/${platform.package}/package.json`),
        path.join(platformRoot, "package.json"),
      ),
      copyFile(
        path.join(repositoryRoot, `flowersec-node-native/target/debug/${platform.library}`),
        path.join(platformRoot, `flowersec-node-native.${platform.package}.node`),
      ),
    ]);
    const moduleRoot = path.join(stagingRoot, "node_modules");
    const nodePath = process.env.NODE_PATH === undefined || process.env.NODE_PATH === ""
      ? moduleRoot
      : `${moduleRoot}${path.delimiter}${process.env.NODE_PATH}`;
    return Object.freeze({
      environment: Object.freeze({
        NODE_PATH: nodePath,
        FLOWERSEC_SERVER_PARITY_NATIVE_ADDON: path.join(wrapperRoot, "index.js"),
      }),
      cleanup: async () => { await rm(stagingRoot, { recursive: true, force: true }); },
    });
  } catch (error) {
    await rm(stagingRoot, { recursive: true, force: true });
    throw error;
  }
}
