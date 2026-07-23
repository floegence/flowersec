import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export const transportV2CommonReadmeLiterals = Object.freeze([
  "WebSocket, raw QUIC, and WebTransport are equal carrier candidates.",
  "QUIC-family carriers use native QUIC streams and never Yamux.",
  "Flowersec application 0-RTT is disabled.",
  "Flowersec does not use QUIC DATAGRAM frames.",
]);

export const transportV2ReadmeContracts = Object.freeze({
  "README.md": "Transport v2 production carrier support: Go native supports WebSocket, raw QUIC, and WebTransport; TypeScript browsers support WebSocket and WebTransport; TypeScript Node.js supports WebSocket dialing for direct clients and both tunnel roles; Rust native supports raw QUIC client dialing; Swift macOS supports WebSocket direct and tunnel dial sessions; Swift iOS advertises no production carrier.",
  "flowersec-go/README.md": "Transport v2 production carrier support: WebSocket, raw QUIC, and WebTransport.",
  "flowersec-ts/README.md": "Transport v2 production carrier support: browsers support WebSocket and WebTransport; Node.js supports WebSocket dialing for direct clients and both tunnel roles.",
  "flowersec-rust/README.md": "Transport v2 production carrier support: raw QUIC client dialing for direct and tunnel paths.",
  "flowersec-swift/README.md": "Transport v2 production carrier support: macOS supports WebSocket direct and tunnel dial sessions; iOS advertises no production carrier.",
  "examples/README.md": "Transport v2 example support: none; the runnable examples remain v1 WebSocket/Yamux examples.",
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
        errors.push(`${file}: missing Transport v2 contract literal: ${literal}`);
      }
    }
    if (!content.includes(supportStatus)) {
      errors.push(`${file}: missing or inaccurate Transport v2 production carrier support status`);
    }
  }
  return errors;
}
