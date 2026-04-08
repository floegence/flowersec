#!/usr/bin/env node

import { connectNode } from "../../flowersec-ts/dist/node/index.js";
import { requestConnectArtifact } from "../../flowersec-ts/dist/controlplane/index.js";

const baseUrl = process.env.FSEC_CONTROLPLANE_BASE_URL || "http://127.0.0.1:8080";
const endpointId = process.env.FSEC_ENDPOINT_ID || "server-1";
const origin = process.env.FSEC_ORIGIN || "http://127.0.0.1:5173";

const artifact = await requestConnectArtifact({
  baseUrl,
  endpointId,
});

const client = await connectNode(artifact, { origin });
try {
  await client.ping();
  process.stdout.write("ok\n");
} finally {
  client.close();
}
