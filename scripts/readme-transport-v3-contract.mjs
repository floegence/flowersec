import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export const transportV3CommonReadmeLiterals = Object.freeze([]);

export const transportV3ReadmeContracts = Object.freeze({
  "README.md": "TLS trust policy is bound to every v3 transport candidate.",
  "flowersec-go/README.md": "Go enforces CA and pin policies",
  "flowersec-ts/README.md": "Browser WebTransport is capability-dependent on",
  "flowersec-rust/README.md": "The native Rust runtime uses WebSocket and raw QUIC for direct and relayed client sessions,",
  "flowersec-swift/README.md": "The Swift SDK supports direct and relayed WebSocket sessions on macOS and iOS.",
  "examples/README.md": "These examples show the public application workflow:",
});

export function validateTransportV3Readmes(repoRoot) {
  const errors = [];
  for (const [file, supportStatus] of Object.entries(transportV3ReadmeContracts)) {
    const readmePath = resolve(repoRoot, file);
    if (!existsSync(readmePath)) {
      errors.push(`${file}: missing README`);
      continue;
    }
    const content = readFileSync(readmePath, "utf8");
    for (const literal of transportV3CommonReadmeLiterals) {
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
