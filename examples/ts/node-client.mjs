import { open, readFile } from "node:fs/promises";
import {
  connectNodeSessionV2,
  createArtifactLeaseV2,
  parseArtifact,
} from "@floegence/flowersec-core/node";

const [artifactPath, origin, receiptPath, trustRootPath] = process.argv.slice(2);
if (artifactPath === undefined || origin === undefined || receiptPath === undefined) {
  throw new Error(
    "usage: node-client.mjs <artifact-json> <origin> <spend-receipt> [trust-root-pem]",
  );
}

const artifact = parseArtifact(await readFile(artifactPath));
const lease = createArtifactLeaseV2(artifact, async () => {
  const receipt = await open(receiptPath, "wx", 0o600);
  try {
    await receipt.writeFile("flowersec-v2-artifact-spent\n", "utf8");
    await receipt.sync();
  } finally {
    await receipt.close();
  }
});
const signal = AbortSignal.timeout(15_000);
const tls = trustRootPath === undefined ? undefined : { ca: await readFile(trustRootPath) };
const session = await connectNodeSessionV2(lease, {
  origin,
  signal,
  ...(tls === undefined ? {} : { tls }),
});
try {
  const roundTripMs = await session.probeLiveness({ signal });
  console.log("session=ready");
  console.log(`liveness_ms=${Math.round(roundTripMs)}`);
} finally {
  await session.close();
}
