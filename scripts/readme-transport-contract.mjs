import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

// Stable public entry points and semantic owners are checked independently of
// localized prose. Runtime support is qualified by the current SDK guides.
export const transportReadmeContracts = Object.freeze({
  "README.md": ["docs/TRANSPORT_V4_BINDING.md", "docs/THREAT_MODEL.md", "local_loopback"],
  "flowersec-go/README.md": ["TransportEnvironment", "ConnectionController"],
  "flowersec-ts/README.md": ["ConnectionController", "TransportEnvironment"],
  "flowersec-rust/README.md": ["TransportEnvironment", "ConnectionController"],
  "flowersec-swift/README.md": ["TransportEnvironment", "ConnectionController", "ServeHandle"],
  "examples/README.md": ["Go", "TypeScript", "Swift", "Rust"],
});

export function validateTransportReadmes(repoRoot) {
  const errors = [];
  for (const [file, literals] of Object.entries(transportReadmeContracts)) {
    const target = resolve(repoRoot, file);
    if (!existsSync(target)) { errors.push(`${file}: missing README`); continue; }
    const content = readFileSync(target, "utf8");
    for (const literal of literals) {
      if (!content.includes(literal)) errors.push(`${file}: missing current public contract: ${literal}`);
    }
    if (/TRANSPORT_V3|flowersec\/3|flowersec-private-loopback\/1/u.test(content)) {
      errors.push(`${file}: retired transport contract remains`);
    }
  }
  return errors;
}
