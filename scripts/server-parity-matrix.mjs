import { readFileSync } from "node:fs";

const capabilityManifest = JSON.parse(readFileSync(
  new URL("../stability/language_capabilities.json", import.meta.url),
  "utf8",
));
const nativeProfile = capabilityManifest.deployment_profiles?.profiles?.find((profile) =>
  profile.id === "native-server-core"
);
if (nativeProfile === undefined ||
    !Array.isArray(nativeProfile.claimed_runtimes) ||
    !Array.isArray(nativeProfile.required_carriers) ||
    !Array.isArray(nativeProfile.required_roles) ||
    nativeProfile.claimed_runtimes.length === 0 ||
    nativeProfile.required_carriers.length === 0 ||
    typeof nativeProfile.required_paths !== "object" ||
    new Set(nativeProfile.claimed_runtimes).size !== nativeProfile.claimed_runtimes.length ||
    new Set(nativeProfile.required_carriers).size !== nativeProfile.required_carriers.length ||
    nativeProfile.required_tuple_count !==
      nativeProfile.claimed_runtimes.length * nativeProfile.required_roles.length * nativeProfile.required_carriers.length ||
    nativeProfile.required_path_unit_count !==
      nativeProfile.claimed_runtimes.length * nativeProfile.required_carriers.length *
        nativeProfile.required_roles.reduce((count, role) => count + (nativeProfile.required_paths[role]?.length ?? 0), 0)) {
  throw new Error("native-server-core capability profile is invalid");
}

export const SERVER_PARITY_RUNTIMES = Object.freeze([...nativeProfile.claimed_runtimes]);
export const SERVER_PARITY_CARRIERS = Object.freeze([...nativeProfile.required_carriers]);

export function generateDirectCellDimensions() {
  return SERVER_PARITY_CARRIERS.flatMap((carrier) =>
    SERVER_PARITY_RUNTIMES.flatMap((client) =>
      SERVER_PARITY_RUNTIMES.map((server) => Object.freeze({
        id: `${runtimeID(client)}_to_${runtimeID(server)}_${carrierID(carrier)}_direct`,
        client,
        server,
        carrier,
      })),
    ),
  );
}

export function generateTunnelTopologyDimensions() {
  return SERVER_PARITY_CARRIERS.flatMap((carrierA) =>
    SERVER_PARITY_CARRIERS.flatMap((carrierB) =>
      SERVER_PARITY_RUNTIMES.flatMap((endpointA, endpointAIndex) =>
        SERVER_PARITY_RUNTIMES.map((tunnelRuntime, relayIndex) => {
          const endpointB = SERVER_PARITY_RUNTIMES[(endpointAIndex + relayIndex) % SERVER_PARITY_RUNTIMES.length];
          const carrierPair = carrierA === carrierB ? carrierID(carrierA) : `${carrierID(carrierA)}_to_${carrierID(carrierB)}`;
          return Object.freeze({
            id: `${runtimeID(endpointA)}_via_${runtimeID(tunnelRuntime)}_to_${runtimeID(endpointB)}_${carrierPair}_tunnel`,
            endpoint_a: endpointA,
            ingress_carrier_a: carrierA,
            tunnel_runtime: tunnelRuntime,
            endpoint_b: endpointB,
            ingress_carrier_b: carrierB,
          });
        }),
      ),
    ),
  );
}

function runtimeID(runtime) {
  return runtime === "node-typescript" ? "node" : runtime;
}

function carrierID(carrier) {
  return carrier === "raw-quic" ? "raw_quic" : carrier;
}

// The execution entrypoint expands independent legs using each original
// persisted runtime/capability cell. A missing native side never becomes a
// supported mixed topology merely because the other side is implemented.
export function executableTunnelTopologies(declared) {
  const byID = new Map(declared.map(topology => [topology.id, topology]));
  const generated = generateTunnelTopologyDimensions();
  return generated.map(dimensions => {
    const original = byID.get(dimensions.id);
    if (original !== undefined) return original;
    const sameA = generated.find(item => item.endpoint_a === dimensions.endpoint_a && item.endpoint_b === dimensions.endpoint_b &&
      item.tunnel_runtime === dimensions.tunnel_runtime && item.ingress_carrier_a === dimensions.ingress_carrier_a && item.ingress_carrier_b === dimensions.ingress_carrier_a);
    const sameB = generated.find(item => item.endpoint_a === dimensions.endpoint_a && item.endpoint_b === dimensions.endpoint_b &&
      item.tunnel_runtime === dimensions.tunnel_runtime && item.ingress_carrier_a === dimensions.ingress_carrier_b && item.ingress_carrier_b === dimensions.ingress_carrier_b);
    const a = byID.get(sameA?.id), b = byID.get(sameB?.id);
    if (a === undefined || b === undefined) throw new Error(`${dimensions.id}: independently installed native capability cells are missing`);
    const supported = a.status === "supported" && b.status === "supported";
    const cases = a.cases.filter(value => value !== "datagram" && value !== "datagram-forwarding");
    return {
      ...dimensions, cases, status: supported ? "supported" : "unsupported",
      ...(supported ? { test_ids: [...a.test_ids] } : { test_ids: [], reason: a.reason ?? b.reason }),
    };
  });
}
