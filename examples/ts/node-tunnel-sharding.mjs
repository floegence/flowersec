import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

// PickTunnelURL selects a stable tunnel URL for a channel using rendezvous hashing (HRW).
//
// Highest-score wins: score = sha256(`${channelId}|${url}`)[:8] interpreted as unsigned big-endian uint64.
export function pickTunnelURL(channelId, urls) {
  let best = "";
  let bestScore = -1n;
  for (const u of urls) {
    const h = createHash("sha256").update(`${channelId}|${u}`).digest();
    const score =
      (BigInt(h[0]) << 56n) |
      (BigInt(h[1]) << 48n) |
      (BigInt(h[2]) << 40n) |
      (BigInt(h[3]) << 32n) |
      (BigInt(h[4]) << 24n) |
      (BigInt(h[5]) << 16n) |
      (BigInt(h[6]) << 8n) |
      BigInt(h[7]);
    if (best === "" || score > bestScore) {
      best = u;
      bestScore = score;
    }
  }
  return best;
}

// Simple CLI for quick checks:
// node ./examples/ts/node-tunnel-sharding.mjs ch_1 wss://a/ws wss://b/ws
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [, , channelId, ...urls] = process.argv;
  if (channelId == null || channelId === "" || urls.length === 0) {
    console.error("usage: node ./examples/ts/node-tunnel-sharding.mjs <channel_id> <url1> [url2 ...]");
    process.exit(2);
  }
  console.log(pickTunnelURL(channelId, urls));
}

