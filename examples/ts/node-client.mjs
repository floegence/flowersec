import { open, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  classifyConnectError,
  classifySessionError,
  connectNodeSession,
  ConnectError,
  createArtifactLease,
  parseArtifact,
  SessionError,
} from "@floegence/flowersec-core/node";

const [artifactPath, origin, receiptPath, trustRootPath] = process.argv.slice(2);
if (artifactPath === undefined || origin === undefined || receiptPath === undefined) {
  throw new Error(
    "usage: node-client.mjs <artifact-json> <origin> <spend-receipt> [trust-root-pem]",
  );
}

const artifact = parseArtifact(await readFile(artifactPath));
const lease = createArtifactLease(artifact, async () => {
  const receipt = await open(receiptPath, "wx", 0o600);
  try {
    await receipt.writeFile("flowersec-v2-artifact-spent\n", "utf8");
    await receipt.sync();
  } finally {
    await receipt.close();
  }
  const directory = await open(dirname(receiptPath), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
});
const signal = AbortSignal.timeout(15_000);
const tls = trustRootPath === undefined ? undefined : { ca: await readFile(trustRootPath) };
let session;
try {
  session = await connectNodeSession(lease, {
    origin,
    signal,
    ...(tls === undefined ? {} : { tls }),
  });
} catch (error) {
  reportRecovery(error);
  throw error;
}
try {
  try {
    const roundTripMs = await session.probeLiveness({ signal });
    console.log("session=ready");
    console.log(`liveness_ms=${Math.round(roundTripMs)}`);
  } catch (error) {
    reportRecovery(error);
    throw error;
  }
} finally {
  await session.close();
}

function reportRecovery(error) {
  if (error instanceof ConnectError) {
    console.error(`recovery=${classifyConnectError(error).action}`);
  } else if (error instanceof SessionError) {
    console.error(`recovery=${classifySessionError(error).action}`);
  }
}
