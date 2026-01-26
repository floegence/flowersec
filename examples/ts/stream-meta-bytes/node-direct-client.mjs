import process from "node:process";

import { connectDirectNode } from "../../../flowersec-ts/dist/node/index.js";
import { DEFAULT_MAX_JSON_FRAME_BYTES, readJsonFrame, writeJsonFrame } from "../../../flowersec-ts/dist/framing/index.js";
import { createByteReader, readNBytes } from "../../../flowersec-ts/dist/streamio/index.js";

// stream-meta-bytes/node-direct-client is a Node.js example for the "meta + bytes" custom stream pattern.
//
// It connects to examples/go/direct_demo and opens a custom stream kind "meta_bytes":
//   request:  JSON meta frame
//   response: JSON meta frame + raw bytes
//
// Notes:
// - The direct demo server enforces Origin allow-list; set FSEC_ORIGIN to an allowed Origin (e.g. http://127.0.0.1:5173).
// - This example allocates a single buffer of size content_len. Keep it small for demos.

async function readStdinUtf8() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

function toHexHead(b, max = 16) {
  const n = Math.min(max, b.length);
  let s = "";
  for (let i = 0; i < n; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

async function main() {
  const input = await readStdinUtf8();
  const info = JSON.parse(input);

  const origin = process.env.FSEC_ORIGIN ?? "";
  if (!origin) throw new Error("missing FSEC_ORIGIN (explicit Origin header value)");

  const wantBytes = Math.max(0, Math.floor(Number(process.env.FSEC_META_BYTES ?? "65536")));
  const fillByte = Math.max(0, Math.min(255, Math.floor(Number(process.env.FSEC_META_FILL_BYTE ?? "97"))));

  const client = await connectDirectNode(info, { origin });
  try {
    const stream = await client.openStream("meta_bytes");
    const reader = createByteReader(stream);

    await writeJsonFrame(stream, { max_bytes: wantBytes, fill_byte: fillByte });
    const meta = await readJsonFrame(reader, DEFAULT_MAX_JSON_FRAME_BYTES);
    console.log("meta:", JSON.stringify(meta));

    if (!meta || typeof meta !== "object" || meta.ok !== true) {
      throw new Error("server returned error meta");
    }
    const contentLen = Math.max(0, Math.floor(Number(meta.content_len ?? 0)));
    const bytes = await readNBytes(reader, contentLen, { chunkSize: 64 * 1024 });
    console.log("bytes:", bytes.length);
    console.log("bytes_head_hex:", toHexHead(bytes));

    await stream.close();
  } finally {
    client.close();
  }
}

await main();

