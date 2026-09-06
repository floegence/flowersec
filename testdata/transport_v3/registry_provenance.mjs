import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const registryPath = process.env.FLOWERSEC_TRANSPORT_REGISTRY_PATH
  ?? join(root, "../../stability/transport_v3_contract.json");

export function loadTransportRegistry() {
  const source = readFileSync(registryPath);
  const registry = JSON.parse(source);
  const registrySha256 = createHash("sha256").update(source).digest("hex");
  const designSource = readFileSync(join(root, "../../", registry.design.source_path));
  const designSha256 = createHash("sha256").update(designSource).digest("hex");
  if (registry.design.sha256 !== designSha256) throw new Error("transport registry design digest mismatch");
  const labels = registry.domain_labels;
  for (const key of ["epoch_zero", "control_root", "stream_root", "setup_root", "rekey_root", "next_epoch", "stream", "record_key", "nonce", "unreliable_root", "unreliable", "unreliable_key", "unreliable_nonce", "unreliable_aad", "setup_mac", "record_aad", "handshake", "server_finished", "client_finished"]) {
    if (typeof labels?.[key] !== "string") throw new Error(`registry domain label missing: ${key}`);
  }
  return { registry, registrySha256, designSha256, labels };
}

export function provenance(source, loaded = loadTransportRegistry()) {
  return { ...source, registry_sha256: loaded.registrySha256, design_sha256: loaded.designSha256 };
}
