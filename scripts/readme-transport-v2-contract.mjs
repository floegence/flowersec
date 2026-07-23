import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export const transportV2CommonReadmeLiterals = Object.freeze([
  "WebSocket, raw QUIC, and WebTransport are equal carrier candidates.",
  "Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior.",
  "Flowersec disables application 0-RTT. Reliable streams never use QUIC DATAGRAM; runtimes with negotiated native DATAGRAM expose it only through carrier-neutral unreliable messages.",
]);

export const transportV2ReadmeContracts = Object.freeze({
  "README.md": "Unsupported carriers fail closed; they are never silent fallbacks.",
  "flowersec-go/README.md": "Transport v2 production carrier support: WebSocket, raw QUIC, and WebTransport.",
  "flowersec-ts/README.md": "Transport v2 production carrier support: browsers support WebSocket and WebTransport; Node.js supports WebSocket dialing for direct clients and both tunnel roles.",
  "flowersec-rust/README.md": "Transport v2 production carrier support: raw QUIC direct client dialing and runtime-owned direct server listening, plus tunnel dialing for both session roles.",
  "flowersec-swift/README.md": "Transport v2 production carrier support: macOS and iOS support WebSocket direct and tunnel dial sessions.",
  "examples/README.md": "Every maintained cookbook is v2-only.",
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
