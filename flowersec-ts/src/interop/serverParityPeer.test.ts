import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile, readFile, unlink, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { testCertificatePEM, testPrivateKeyPEM } from "../testSupport/tlsFixture.js";
import {
  parseArguments, publishCurrentParityMaterial, readCurrentParityMaterialPublication, requireCurrentRelay,
  requireCurrentRelayAcknowledgment, requireCurrentListenerTLS, runCurrentV4EndpointA,
  type CurrentRelayReady, type CurrentParityMaterialPublication, type ParityPeerInput,
} from "./serverParityPeer.js";

const directories = new Set<string>();
afterEach(async () => { for (const path of directories) { await rm(path, { recursive: true, force: true }); directories.delete(path); } });
async function publicationPath(): Promise<string> {
  const path = await mkdtemp(join(dirname(fileURLToPath(new URL("../../..", import.meta.url))), "flowersec-ts-parity-publication-test-"));
  directories.add(path); return join(path, "material.json");
}
function ready(): CurrentRelayReady {
  return {
    type: "relay-ready", runtime: "go", carrier: "websocket", server_carrier: "raw-quic", path: "tunnel", wire_revision: 4,
    profile: "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", source: "preauthorized_pool",
    material_digest: "a".repeat(64), route_digest: Buffer.alloc(32, 1).toString("base64"),
    trust_pem: testCertificatePEM, origin: "https://client.example",
  };
}
const material: CurrentParityMaterialPublication = { wire_revision: 4, endpoint_a_artifact_json: "original-client", endpoint_b_artifact_json: "original-server" };

describe("current parity CLI contracts", () => {
  it("selects the single current wire engine for every role", () => {
    for (const role of ["server", "client", "relay", "tunnel-endpoint-a", "tunnel-endpoint-b"]) {
      expect(parseArguments([role, "--carrier", "websocket"]).wireRevision).toBe(4);
      expect(parseArguments([role, "--carrier", "websocket", "--wire-revision", "4"]).wireRevision).toBe(4);
      expect(() => parseArguments([role, "--carrier", "websocket", "--wire-revision", "3"])).toThrow("invalid parity option");
    }
  });
  it("binds the two relay carriers independently", () => {
    const parsed = parseArguments(["relay", "--carrier", "raw-quic", "--server-carrier", "websocket", "--deployment", "/trusted/relay.json"]);
    expect(parsed.carrier).toBe("raw-quic"); expect(parsed.serverCarrier).toBe("websocket"); expect(parsed.deploymentPath).toBe("/trusted/relay.json");
    expect(() => parseArguments(["tunnel-endpoint-b", "--carrier", "raw-quic", "--server-carrier", "websocket"])).toThrow("current relay role");
    expect(() => parseArguments(["relay", "--carrier", "raw-quic", "--wire-revision", "3", "--server-carrier", "websocket"])).toThrow("invalid parity option");
  });
  it("refuses incomplete, duplicate or misplaced deployment options", () => {
    expect(() => parseArguments(["relay", "--carrier", "websocket", "--server-carrier"])).toThrow("invalid parity option");
    expect(() => parseArguments(["relay", "--carrier", "websocket", "--wire-revision", "4", "--wire-revision", "3"])).toThrow("invalid parity option");
    expect(() => parseArguments(["client", "--carrier", "websocket", "--deployment", "/trusted/relay.json"])).toThrow("current relay or registered B role");
    expect(() => parseArguments(["tunnel-endpoint-b", "--carrier", "websocket", "--material-publication", "relative.json"])).toThrow("absolute material publication path");
  });
  it("does not treat a V3 or partial relay envelope as current publication", () => {
    expect(() => requireCurrentRelay(ready())).not.toThrow();
    expect(() => requireCurrentRelay(null)).toThrow("ready envelope");
    expect(() => requireCurrentRelay({ ...ready(), wire_revision: 3 })).toThrow("original relay issuance");
    expect(() => requireCurrentRelay({ ...ready(), endpoint_a_artifact_json: "client" })).toThrow("original relay issuance");
    expect(() => requireCurrentRelay({ ...ready(), route_digest: "AQ==" })).toThrow("route digest");
    expect(() => requireCurrentRelay({ ...ready(), source: "live_authority", material_digest: undefined })).toThrow("original relay issuance");
  });
  it("compares an acknowledgement only against the original detached publication", () => {
    const original: CurrentRelayReady = { ...ready(), authorizations: [{ candidate_index: 0, role: 0, grant: "AQ==", endpoint_certificate: "Ag==", relay_certificate: "Aw==", grant_namespace: 0, endpoint_namespace: 0, relay_namespace: 0 }], verification_records: [] };
    expect(() => requireCurrentRelayAcknowledgment({ type: "configure", wire_revision: 4, route_digest: original.route_digest, authorizations: original.authorizations!, verification_records: original.verification_records! }, original)).not.toThrow();
    expect(() => requireCurrentRelayAcknowledgment({ type: "configure", wire_revision: 4, route_digest: original.route_digest, authorizations: structuredClone(original.authorizations!), verification_records: [] }, original)).not.toThrow();
    expect(() => requireCurrentRelayAcknowledgment({ type: "configure", wire_revision: 4, route_digest: Buffer.alloc(32, 2).toString("base64") }, original)).toThrow("original committed publication");
    expect(() => requireCurrentRelayAcknowledgment({ type: "configure", wire_revision: 4, route_digest: original.route_digest, authorizations: [] }, original)).toThrow("original committed publication");
    expect(() => requireCurrentRelayAcknowledgment({ type: "configure", wire_revision: 3 as unknown as 4, route_digest: original.route_digest }, original)).toThrow("original committed publication");
  });
  it("requires endpoint B to match the server carrier before any current connection", async () => {
    const input: ParityPeerInput = { next: async <T>() => ({
      topology: { id: "mixed", endpoint_a: "node-typescript", endpoint_b: "go", tunnel_runtime: "go", ingress_carrier_a: "websocket", ingress_carrier_b: "raw-quic" },
      endpoint_b: { type: "endpoint-b-ready", runtime: "go", carrier: "websocket", path: "tunnel", wire_revision: 4, relay: ready() },
    }) as T };
    await expect(runCurrentV4EndpointA(input, "websocket")).rejects.toThrow("endpoint B envelope");
  });
  it("uses the delivered original server listener TLS key", () => {
    expect(() => requireCurrentListenerTLS(testCertificatePEM, testPrivateKeyPEM)).not.toThrow();
    const other = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "pem" });
    expect(() => requireCurrentListenerTLS(testCertificatePEM, other)).toThrow("original local deployment");
    expect(() => requireCurrentListenerTLS(testCertificatePEM, undefined)).toThrow("complete original TLS deployment");
  });
});

describe("original parity material publication", () => {
  it("publishes the exact paired bytes once with private file permissions", async () => {
    const path = await publicationPath(), owner = await publishCurrentParityMaterial(path, material);
    try {
      const bytes = await readFile(path);
      expect(owner.digest).toBe(createHash("sha256").update(bytes).digest("hex"));
      expect((await stat(path)).mode & 0o777).toBe(0o600);
      expect(await readCurrentParityMaterialPublication(path, owner.digest)).toEqual(material);
      await expect(publishCurrentParityMaterial(path, material)).rejects.toThrow();
    } finally { await owner.close(); }
    await expect(readFile(path)).rejects.toMatchObject({ code: "ENOENT" });
  });
  it("refuses a modified publication under the original digest", async () => {
    const path = await publicationPath(), owner = await publishCurrentParityMaterial(path, material);
    try {
      await writeFile(path, JSON.stringify({ ...material, endpoint_b_artifact_json: "substituted-server" }));
      await expect(readCurrentParityMaterialPublication(path, owner.digest)).rejects.toThrow("publication binding failed");
    } finally { await owner.close(); }
  });
  it("does not remove a different file that replaced its original publication", async () => {
    const path = await publicationPath(), owner = await publishCurrentParityMaterial(path, material);
    await unlink(path); await writeFile(path, "replacement", { flag: "wx" });
    await expect(owner.close()).rejects.toThrow("ownership changed");
    expect(await readFile(path, "utf8")).toBe("replacement");
  });
});
