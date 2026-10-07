import { isDeepStrictEqual } from "node:util";

// Engineering peer envelopes contain original signed maps and independently
// pinned namespace records. Each SDK consumer performs its own fresh nonce
// bootstrap and normal signature/authorization admission.
const profiles = new Set([
  "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1",
  "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1",
]);

export function assertCurrentPeer(message, id) {
  if (message.wire_revision !== 4 || !profiles.has(message.profile) ||
      typeof message.source !== "string" || message.source.length === 0) {
    throw new Error(`${id}: peer must identify its current wire revision, signed profile and material source`);
  }
}

function bytes(value, field, id, length) {
  if (typeof value !== "string" || value.length === 0 || value.length > 2_097_152) {
    throw new Error(`${id}: ${field} must contain bounded original base64 bytes`);
  }
  const decoded = Buffer.from(value, "base64");
  try {
    if (decoded.length === 0 || decoded.toString("base64") !== value ||
        (length !== undefined && decoded.length !== length)) {
      throw new Error(`${id}: ${field} has an invalid base64 encoding or length`);
    }
  } finally { decoded.fill(0); }
}

export function assertNamespaceRecords(records, id) {
  if (!Array.isArray(records) || records.length === 0 || records.length > 16) {
    throw new Error(`${id}: expected one to sixteen independent namespace records`);
  }
  const domains = new Set();
  for (const [index, record] of records.entries()) {
    if (record === null || typeof record !== "object" ||
        !Number.isSafeInteger(record.generation) || record.generation < 1) {
      throw new Error(`${id}: namespace ${index} has no exact generation`);
    }
    for (const field of ["tenant", "authority"]) {
      if (typeof record[field] !== "string" || !/^[a-z0-9][a-z0-9._:/@-]{0,127}$/.test(record[field])) {
        throw new Error(`${id}: namespace ${index} has an invalid ${field}`);
      }
    }
    const domain = JSON.stringify([record.tenant, record.authority]);
    if (domains.has(domain)) throw new Error(`${id}: duplicate namespace pin`);
    domains.add(domain);
    bytes(record.root_key_id, "root_key_id", id, 16);
    bytes(record.root_public_key, "root_public_key", id, 32);
    for (const field of ["bootstrap_url", "state_url"]) {
      const url = new URL(record[field]);
      if (!["http:", "https:"].includes(url.protocol) || url.username !== "" || url.password !== "") {
        throw new Error(`${id}: namespace ${index} has an invalid ${field}`);
      }
    }
    if (Object.hasOwn(record, "nonce") || Object.hasOwn(record, "response")) {
      throw new Error(`${id}: namespace bootstrap must be requested with the consumer's fresh nonce`);
    }
  }
}

function namespaceIndex(value, records, field, id) {
  if (!Number.isInteger(value) || value < 0 || value >= records.length) {
    throw new Error(`${id}: ${field} does not identify an independent namespace record`);
  }
}

export function assertCurrentMaterial(artifactJSON, id, peer) {
  if (typeof artifactJSON !== "string" || artifactJSON.length === 0 || artifactJSON.length > 16_777_216) {
    throw new Error(`${id}: peer did not publish a bounded current material bundle`);
  }
  const material = JSON.parse(artifactJSON);
  assertCurrentPeer(material, id);
  if (peer !== undefined && (material.profile !== peer.profile || material.source !== peer.source)) {
    throw new Error(`${id}: material does not match the peer's profile and source`);
  }
  if (![0, 1].includes(material.role) || material.generation === null || typeof material.generation !== "object" ||
      !Number.isSafeInteger(material.generation.generation) || material.generation.generation < 1) {
    throw new Error(`${id}: material has no bounded original source generation and role`);
  }
  bytes(material.generation.source, "generation.source", id, 16);
  for (const field of ["artifact", "client_certificate", "server_certificate", "route"]) bytes(material[field], field, id);
  if (material.source === "preauthorized_pool") {
    bytes(material.activation, "activation", id);
    if (Object.hasOwn(material, "live_control_base_url")) throw new Error(`${id}: pool material contains a live authority`);
  } else if (material.source === "live_authority") {
    if (!Object.hasOwn(material, "activation") || material.activation !== null && material.activation !== "") {
      throw new Error(`${id}: live material must retain its original pending activation`);
    }
    const endpoint = new URL(material.live_control_base_url);
    if (typeof material.live_control_base_url !== "string" || material.live_control_base_url.length > 2048
        || endpoint.protocol !== "https:" || endpoint.username !== "" || endpoint.password !== "" || endpoint.hash !== ""
        || endpoint.search !== "" || endpoint.pathname !== "/flowersec/control/live") {
      throw new Error(`${id}: live material lacks its independently installed registered control endpoint`);
    }
  } else { throw new Error(`${id}: unsupported original material source`); }
  bytes(material.route_digest, "route_digest", id, 32);
  bytes(material.identity_seed, "identity_seed", id, 32);
  bytes(material.dh_seed, "dh_seed", id, 32);
  if (typeof material.activation_signing_key_id !== "string" || material.activation_signing_key_id.length === 0) {
    throw new Error(`${id}: missing activation signer identifier`);
  }
  assertNamespaceRecords(material.namespaces, id);
  // encoding/json represents an empty slice as null; both forms mean no
  // tunnel candidate. Actual candidates retain their bounded original maps.
  const tunnels = material.tunnels ?? [];
  if (!Array.isArray(tunnels) || tunnels.length > 16) throw new Error(`${id}: too many tunnel candidates`);
  for (const tunnel of tunnels) {
    if (!Number.isSafeInteger(tunnel.candidate_index) || tunnel.candidate_index < 0 || ![0, 1].includes(tunnel.role)) {
      throw new Error(`${id}: invalid tunnel candidate association`);
    }
    bytes(tunnel.relay_certificate, "relay_certificate", id);
    if (material.source === "preauthorized_pool") {
      bytes(tunnel.grant, "grant", id);
      if (Object.hasOwn(tunnel, "live_grant")) throw new Error(`${id}: pool slot contains a pending live Grant policy`);
    } else {
      if (Object.hasOwn(tunnel, "grant")) throw new Error(`${id}: live slot already contains a detached Grant`);
      const pending = tunnel.live_grant;
      const fields = ["authority", "issuer_key_id", "audience", "service", "revocation_policy_id", "revocation_policy_revision", "max_not_after_ms"];
      if (pending === null || typeof pending !== "object" || !isDeepStrictEqual(Object.keys(pending).sort(), fields.sort())) {
        throw new Error(`${id}: live slot lacks its exact installed pending Grant policy`);
      }
      for (const field of ["authority", "audience", "service", "revocation_policy_id"]) {
        if (typeof pending[field] !== "string" || !/^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(pending[field])) {
          throw new Error(`${id}: invalid installed live Grant ${field}`);
        }
      }
      bytes(pending.issuer_key_id, "live_grant.issuer_key_id", id, 16);
      for (const field of ["revocation_policy_revision", "max_not_after_ms"]) {
        if (typeof pending[field] !== "string" || !/^[1-9][0-9]{0,19}$/u.test(pending[field]) || BigInt(pending[field]) > 18446744073709551615n) {
          throw new Error(`${id}: noncanonical installed live Grant ${field}`);
        }
      }
    }
    namespaceIndex(tunnel.grant_namespace, material.namespaces, "grant_namespace", id);
    namespaceIndex(tunnel.relay_namespace, material.namespaces, "relay_namespace", id);
    if (material.source === "live_authority" && tunnel.live_grant.authority !== material.namespaces[tunnel.grant_namespace].authority) {
      throw new Error(`${id}: live Grant issuer authority differs from its installed namespace`);
    }
  }
  if (tunnels.length > 0) {
    const deployment = material.relay_deployment;
    if (deployment === null || typeof deployment !== "object" || !isDeepStrictEqual(Object.keys(deployment).sort(), ["Profile", "RouteDigest"]) || typeof deployment.Profile !== "string" ||
        deployment.Profile.length === 0 || deployment.Profile.length > 128 || !Array.isArray(deployment.RouteDigest) ||
        deployment.RouteDigest.length !== 32 || !deployment.RouteDigest.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255) ||
        !Buffer.from(deployment.RouteDigest).equals(Buffer.from(material.route_digest, "base64"))) {
      throw new Error(`${id}: tunnel material lacks its independently installed exact relay deployment`);
    }
  }
  return material;
}

export function assertTunnelAuthorizations(authorizations, records, id) {
  assertNamespaceRecords(records, id);
  if (!Array.isArray(authorizations) || authorizations.length !== 2) {
    throw new Error(`${id}: relay requires the two original signed leg authorizations`);
  }
  const roles = new Set();
  for (const authorization of authorizations) {
    if (!Number.isSafeInteger(authorization.candidate_index) || authorization.candidate_index < 0 ||
        ![0, 1].includes(authorization.role) || roles.has(authorization.role)) {
      throw new Error(`${id}: relay leg association must retain exactly one role per endpoint`);
    }
    roles.add(authorization.role);
    for (const field of ["grant", "endpoint_certificate", "relay_certificate"]) bytes(authorization[field], field, id);
    for (const field of ["grant_namespace", "endpoint_namespace", "relay_namespace"]) namespaceIndex(authorization[field], records, field, id);
    for (const field of ["decision", "credentialId", "leaseId", "expiresAtUnixSeconds", "allowReplacement"]) {
      if (Object.hasOwn(authorization, field)) throw new Error(`${id}: relay authorization contains a superseded decision hint`);
    }
  }
}

// Scenario helpers retain application addressing separately from signed
// transport material. Consumers still obtain the actual Leg from the bundle.
export function assertPrivateLoopbackPeer(peer, id) {
  const material = assertCurrentMaterial(peer.artifact_json, id, peer);
  const origin = new URL(peer.origin);
  if (origin.protocol !== "http:" || origin.hostname !== "127.0.0.1" || origin.port === "" ||
      origin.username !== "" || origin.password !== "" || origin.pathname !== "/" ||
      origin.search !== "" || origin.hash !== "" || typeof peer.bridge_token !== "string" ||
      peer.bridge_token.length === 0 || peer.bridge_token.length > 4096) {
    throw new Error(`${id}: local bridge requires its exact numeric HTTP origin and explicit bounded token`);
  }
  if (typeof peer.trust_pem !== "string" || !peer.trust_pem.startsWith("-----BEGIN CERTIFICATE-----\n") ||
      material.namespaces.some(record => new URL(record.bootstrap_url).protocol !== "https:")) {
    throw new Error(`${id}: local WS material requires independent fresh HTTPS namespace bootstrap trust`);
  }
  return material;
}

export function assertHTTPDirectMaterialPositions(originValue, materialJSONs, id) {
  const origin = new URL(originValue);
  if (origin.protocol !== "http:" || origin.hostname !== "127.0.0.1" || origin.port === "" ||
      origin.username !== "" || origin.password !== "" || origin.pathname !== "/" ||
      origin.search !== "" || origin.hash !== "" || !Array.isArray(materialJSONs) || materialJSONs.length !== 2) {
    throw new Error(`${id}: HTTP-direct requires one numeric application origin and exactly two material positions`);
  }
  const materials = materialJSONs.map((material, index) => assertCurrentMaterial(material, `${id} position ${index}`));
  if (materials[0].artifact === materials[1].artifact || materials[0].activation === materials[1].activation) {
    throw new Error(`${id}: HTTP-direct positions must retain independent original signed pool leases`);
  }
  return materials;
}

// This envelope check preserves the source's complete original publication.
// Actual namespace bootstrap, signature checks, HOP_AUTH and durable admission
// remain the responsibilities of each SDK owner consuming these same bytes.
export function assertTunnelPublication(relay, id) {
  assertCurrentPeer(relay, id);
  const client = assertCurrentMaterial(relay.endpoint_a_artifact_json, `${id} endpoint A`, relay);
  const server = assertCurrentMaterial(relay.endpoint_b_artifact_json, `${id} endpoint B`, relay);
  if (client.role !== 0 || server.role !== 1 || !["preauthorized_pool", "live_authority"].includes(client.source) ||
      typeof relay.route_digest !== "string" || relay.route_digest !== client.route_digest) {
    throw new Error(`${id}: relay publication lacks the original paired source and exact route`);
  }
  for (const field of ["artifact", "activation", "client_certificate", "server_certificate", "route", "route_digest", "profile", "source", "generation", "namespaces", "tunnels", "activation_signing_key_id", "relay_deployment"]) {
    if (!isDeepStrictEqual(client[field], server[field])) throw new Error(`${id}: original endpoint records disagree on ${field}`);
  }
  if (!Array.isArray(client.tunnels) || client.tunnels.length !== 2 || new Set(client.tunnels.map(tunnel => tunnel.role)).size !== 2 ||
      client.tunnels[0].candidate_index !== client.tunnels[1].candidate_index) {
    throw new Error(`${id}: each endpoint must retain both original leg records`);
  }
  if (client.source === "preauthorized_pool") {
    assertTunnelAuthorizations(relay.authorizations, relay.verification_records, id);
  } else {
    assertNamespaceRecords(relay.verification_records, id);
    if (!Array.isArray(relay.authorizations) || relay.authorizations.length !== 0
        || client.live_control_base_url !== server.live_control_base_url) {
      throw new Error(`${id}: pending live publication contains detached authorizations or a different original authority`);
    }
  }
  if (!isDeepStrictEqual(relay.verification_records, client.namespaces)) throw new Error(`${id}: relay namespace projection altered original publication`);
  for (const authorization of relay.authorizations) {
    const original = client.tunnels.find(tunnel => tunnel.role === authorization.role);
    const endpoint = authorization.role === 0 ? client.client_certificate : client.server_certificate;
    if (original === undefined || authorization.candidate_index !== original.candidate_index || authorization.grant !== original.grant ||
        authorization.endpoint_certificate !== endpoint || authorization.relay_certificate !== original.relay_certificate ||
        authorization.grant_namespace !== original.grant_namespace || authorization.relay_namespace !== original.relay_namespace || authorization.endpoint_namespace !== 0) {
      throw new Error(`${id}: relay authorization differs from its original committed leg tuple`);
    }
  }
  for (const side of ["client", "server"]) {
    if (typeof relay[`${side}_tls_certificate_pem`] !== "string" || relay[`${side}_tls_certificate_pem`].length === 0 || relay[`${side}_tls_certificate_pem`].length > 262144 ||
        typeof relay[`${side}_tls_private_key_pem`] !== "string" || relay[`${side}_tls_private_key_pem`].length === 0 || relay[`${side}_tls_private_key_pem`].length > 65536) {
      throw new Error(`${id}: endpoint listener requires its independent native TLS manifest`);
    }
  }
  return { client, server };
}

export function assertRoleBoundLiveTunnelPublication(relay, role, id) {
  assertCurrentPeer(relay, id);
  if (relay.source !== "live_authority" || ![0, 1].includes(role)) throw new Error(`${id}: invalid original live endpoint role`);
  const own = role === 0 ? "endpoint_a_artifact_json" : "endpoint_b_artifact_json";
  const opposite = role === 0 ? "endpoint_b_artifact_json" : "endpoint_a_artifact_json";
  const oppositeTLS = role === 0 ? "server_tls_private_key_pem" : "client_tls_private_key_pem";
  if (relay[opposite] !== "" || relay[oppositeTLS] !== "") throw new Error(`${id}: endpoint received another role's private material`);
  const material = assertCurrentMaterial(relay[own], id, relay);
  if (material.role !== role || material.route_digest !== relay.route_digest || !isDeepStrictEqual(material.namespaces, relay.verification_records)
      || !Array.isArray(relay.authorizations) || relay.authorizations.length !== 0 || !Array.isArray(material.tunnels)
      || material.tunnels.length !== 2 || new Set(material.tunnels.map(tunnel => tunnel.role)).size !== 2
      || material.tunnels[0].candidate_index !== material.tunnels[1].candidate_index) {
    throw new Error(`${id}: own live material differs from its original route, namespace or pending leg binding`);
  }
  return material;
}

export function assertEndpointTunnelPublication(endpoint, relay, id) {
  assertCurrentPeer(endpoint, id);
  if (endpoint.profile !== relay.profile || endpoint.source !== relay.source) throw new Error(`${id}: endpoint B changed the original source or signed profile`);
  if (endpoint.endpoint_a_artifact_json !== relay.endpoint_a_artifact_json || endpoint.endpoint_b_artifact_json !== relay.endpoint_b_artifact_json ||
      !isDeepStrictEqual(endpoint.authorizations, relay.authorizations) || !isDeepStrictEqual(endpoint.verification_records, relay.verification_records)) {
    throw new Error(`${id}: endpoint B altered original authority publication`);
  }
  if (relay.source === "preauthorized_pool") {
    const binding = endpoint.server_allow;
    if (binding === null || typeof binding !== "object" || Array.isArray(binding) || Object.keys(binding).length !== 3 ||
        typeof binding.endpoint !== "string" || binding.endpoint.length > 2048) throw new Error(`${id}: pool B must expose only its original Allow endpoint and public registration`);
    const address = new URL(binding.endpoint);
    if (address.protocol !== "https:" || !["127.0.0.1", "[::1]"].includes(address.hostname) || (address.port === "" || address.port === "0") || address.pathname !== "/tunnel/server-allow" || address.username !== "" || address.password !== "" || address.search !== "" || address.hash !== "") throw new Error(`${id}: pool B Allow endpoint differs from its installed numeric loopback service`);
    for (const field of ["recipient", "incarnation"]) {
      bytes(binding[field], `original Allow ${field}`, id, 16);
      const decoded = Buffer.from(binding[field], "base64");
      try { if (decoded.every(value => value === 0)) throw new Error(`${id}: original B Allow ${field} cannot be empty`); }
      finally { decoded.fill(0); }
    }
  }
  return relay.source === "live_authority" && relay.endpoint_a_artifact_json === ""
    ? assertRoleBoundLiveTunnelPublication(relay, 1, id) : assertTunnelPublication(relay, id);
}

// Completion is reported only after joining the real owning SDK/provider tails.
// A peer cannot substitute an externally supplied cleanup count for that join.
export function assertNoSyntheticCleanupCounters(message, id) {
  for (const field of ["active_pairs", "active_legs", "active_sessions", "active_streams", "application_handlers", "released_leases"]) {
    if (Object.hasOwn(message, field)) throw new Error(`${id}: synthetic cleanup counter ${field} is forbidden`);
  }
}
