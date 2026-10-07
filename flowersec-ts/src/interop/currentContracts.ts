import { map, text, u, array, encode } from "../v4/testSupport/credentials.js";

/** Exact application fixture contracts shared with Go EngineeringServiceContract.
 * These are the corpus service_unary_transient/service_notify_observation
 * templates with only namespace, type, request bound, response bound and the
 * declared lifetime/run maximum changed. Each SDK verifies/digests the actual
 * canonical bytes through its ordinary ServiceContract owner. */
export function currentPeerContract(typeID: 7001 | 7002 | 7003 | 7005): Uint8Array {
  const notify = typeID === 7002;
  return encode(map({
    0: text("flowersec.parity"), 1: u(typeID), 2: u(notify ? 2 : 0), [notify ? 5 : 3]: u(0),
    6: text("1"), 7: text("1"), 8: u(notify ? 0 : 1), 9: u(0), 10: u(notify ? 0 : 4096), 11: u(30000),
    ...(notify ? {} : { 12: u(30000) }), 21: { kind: "bool", value: false }, 23: u(4096), 27: array(),
  }));
}
