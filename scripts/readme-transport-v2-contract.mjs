import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export const transportV2CommonReadmeLiterals = Object.freeze([]);

export const transportV2ReadmeContracts = Object.freeze({
  "README.md": "Application data is encrypted end to end for both direct and relayed sessions.",
  "flowersec-go/README.md": "it is not a supported endpoint-client\ntunnel path or `TunnelRuntime` capability",
  "flowersec-ts/README.md": "Browser WebTransport is capability-dependent on",
  "flowersec-rust/README.md": "The native Rust runtime uses WebSocket and raw QUIC for direct and relayed client sessions,",
  "flowersec-swift/README.md": "The Swift SDK supports direct and relayed WebSocket sessions on macOS and iOS.",
  "examples/README.md": "These examples show the public application workflow:",
});

export function validateTransportV2Readmes(repoRoot) {
  const errors = [];
  for (const [file, supportStatus] of Object.entries(transportV2ReadmeContracts)) {
    const readmePath = resolve(repoRoot, file);
    if (!existsSync(readmePath)) {
      errors.push(`${file}: missing README`);
      continue;
    }
    const content = readFileSync(readmePath, "utf8");
    for (const literal of transportV2CommonReadmeLiterals) {
      if (!content.includes(literal)) {
        errors.push(`${file}: missing shared README contract literal: ${literal}`);
      }
    }
    if (!content.includes(supportStatus)) {
      errors.push(`${file}: missing current user-facing support description`);
    }
  }
  return errors;
}
