import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(pkgRoot, '..');
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'flowersec-package-verify-'));
const packDir = path.join(tmpRoot, 'pack');
const consumerDir = path.join(tmpRoot, 'consumer');
const manifest = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'stability', 'api_contract_manifest.json'), 'utf8')
);
const forbiddenRuntimeExportsBySubpath = new Map([
  ['@floegence/flowersec-core/proxy', ['resolveNamedProxyPreset', 'CODESERVER_PROXY_PRESET_MANIFEST']],
]);
const removedLegacyRuntimeExports = new Set([
  'requestChannelGrant',
  'requestEntryChannelGrant',
  'establishSessionV2',
  'AdmissionSessionV2Error',
  'establishAdmittedNativeSessionV2',
  'establishAdmittedWebSocketSessionV2',
]);
const removedImplementationSubpaths = [
  'framing',
  'yamux',
  'e2ee',
  'ws',
  'streamhello',
  'gen/flowersec/controlplane/v1',
  'gen/flowersec/direct/v1',
  'gen/flowersec/e2ee/v1',
  'gen/flowersec/rpc/v1',
  'gen/flowersec/tunnel/v1',
];

function isRemovedLegacyPackageExport(subpath) {
  return subpath === './internal' || subpath.startsWith('./internal/');
}

function run(cmd, args, cwd, input) {
  return execFileSync(cmd, args, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
    ...(input == null ? {} : { input }),
  });
}

function packTarball() {
  fs.mkdirSync(packDir, { recursive: true });
  try {
    return run('npm', ['pack', '--silent', '--ignore-scripts', '--pack-destination', packDir], pkgRoot).trim();
  } catch {
    const name = run('npm', ['pack', '--silent', '--ignore-scripts'], pkgRoot).trim();
    fs.renameSync(path.join(pkgRoot, name), path.join(packDir, name));
    return name;
  }
}

function installTarball(tarballPath) {
  fs.mkdirSync(consumerDir, { recursive: true });
  fs.writeFileSync(
    path.join(consumerDir, 'package.json'),
    JSON.stringify({ name: 'flowersec-package-verify', private: true, type: 'module' }, null, 2)
  );
  run('npm', ['install', '--ignore-scripts', '--no-package-lock', tarballPath], consumerDir);
}

function verifyBrowserDependencyGraph() {
  const entry = path.join(
    consumerDir,
    'node_modules',
    '@floegence',
    'flowersec-core',
    'dist',
    'browser',
    'index.js'
  );
  const pending = [entry];
  const visited = new Set();
  const bareSpecifiers = [];
  while (pending.length > 0) {
    const file = pending.pop();
    if (visited.has(file)) continue;
    visited.add(file);
    const source = fs.readFileSync(file, 'utf8');
    for (const match of source.matchAll(/(?:from\s+|import\s*)["']([^"']+)["']/g)) {
      const specifier = match[1];
      if (!specifier.startsWith('.')) {
        bareSpecifiers.push(specifier);
        continue;
      }
      pending.push(path.resolve(path.dirname(file), specifier));
    }
  }
  assert.equal(bareSpecifiers.includes('tr46'), false, 'browser dependency graph must bundle tr46');
}

function verifyPackageJSONExports() {
  const pkg = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
  for (const subpath of Object.keys(pkg.exports)) {
    assert.equal(isRemovedLegacyPackageExport(subpath), false, `package.json exports removed legacy subpath ${subpath}`);
  }
  const stableExports = Object.keys(pkg.exports).filter((subpath) => !subpath.includes('*'));
  const manifestExports = manifest.ts.subpaths.map((subpath) => subpath.package_json_export);
  for (const subpath of manifest.ts.subpaths) {
    assert.equal(
      Object.prototype.hasOwnProperty.call(pkg.exports, subpath.package_json_export),
      true,
      `package.json exports missing ${subpath.package_json_export}`
    );
  }
  assert.deepEqual([...manifestExports].sort(), [...stableExports].sort(), 'stable package.json exports and manifest subpaths must match');
}

function verifyInstalledPackage() {
  const checks = manifest.ts.subpaths.map((subpath, index) => {
    const moduleVar = `mod${index}`;
    const lines = [
      `    const ${moduleVar} = await import(${JSON.stringify(subpath.specifier)});`
    ];
    for (const exportName of subpath.runtime_exports) {
      lines.push(
        `    assert.equal(Object.prototype.hasOwnProperty.call(${moduleVar}, ${JSON.stringify(exportName)}), true, ${JSON.stringify(subpath.specifier + ' missing export ' + exportName)});`
      );
      lines.push(
        `    assert.notEqual(${moduleVar}[${JSON.stringify(exportName)}], undefined, ${JSON.stringify(subpath.specifier + ' export is undefined: ' + exportName)});`
      );
    }
    for (const exportName of forbiddenRuntimeExportsBySubpath.get(subpath.specifier) ?? []) {
      lines.push(
        `    assert.equal(Object.prototype.hasOwnProperty.call(${moduleVar}, ${JSON.stringify(exportName)}), false, ${JSON.stringify(subpath.specifier + ' leaked forbidden export ' + exportName)});`
      );
    }
    for (const exportName of removedLegacyRuntimeExports) {
      lines.push(
        `    assert.equal(Object.prototype.hasOwnProperty.call(${moduleVar}, ${JSON.stringify(exportName)}), false, ${JSON.stringify(subpath.specifier + ' leaked removed legacy export ' + exportName)});`
      );
    }
    return lines.join('\n');
  }).join('\n\n');

  const script = `
    import assert from 'node:assert/strict';
${checks}

    for (const subpath of ${JSON.stringify(removedImplementationSubpaths)}) {
      await assert.rejects(
        import('@floegence/flowersec-core/' + subpath),
        (error) => error?.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
        'removed implementation subpath remained runtime-importable: ' + subpath,
      );
    }

    const reconnect = await import('@floegence/flowersec-core/reconnect');
    const mgr = reconnect.createReconnectManager();
    assert.equal(typeof mgr.connectIfNeeded, 'function');

    const browser = await import('@floegence/flowersec-core/browser');
    assert.equal(typeof browser.requestConnectArtifact, 'function');
    assert.equal(typeof browser.requestEntryConnectArtifact, 'function');
    assert.equal(Object.prototype.hasOwnProperty.call(browser, 'createBrowserWebTransportCarrierInternalStage'), false);
    assert.deepEqual(browser.BROWSER_RUNTIME_CAPABILITY_V2, {
      language: 'typescript',
      runtime: 'browser',
      schemaVersion: 2,
      tuples: [
        { carrier: 'websocket', networkMode: 'dial', path: 'direct', sessionRole: 'client' },
        { carrier: 'websocket', networkMode: 'dial', path: 'tunnel', sessionRole: 'client' },
        { carrier: 'websocket', networkMode: 'dial', path: 'tunnel', sessionRole: 'server' },
        { carrier: 'webtransport', networkMode: 'dial', path: 'direct', sessionRole: 'client' },
        { carrier: 'webtransport', networkMode: 'dial', path: 'tunnel', sessionRole: 'client' },
        { carrier: 'webtransport', networkMode: 'dial', path: 'tunnel', sessionRole: 'server' },
      ],
      unsupported: [{ carrier: 'raw_quic', reason: 'browser_no_raw_udp' }],
    });
    assert.equal(browser.NODE_RUNTIME_CAPABILITY_V2, undefined);

    const node = await import('@floegence/flowersec-core/node');
    assert.deepEqual(node.NODE_RUNTIME_CAPABILITY_V2, {
      language: 'typescript',
      runtime: 'node',
      schemaVersion: 2,
      tuples: [],
      unsupported: [
        { carrier: 'raw_quic', reason: 'no_production_grade_node_quic_runtime' },
        { carrier: 'websocket', reason: 'transport_v2_websocket_adapter_not_committed' },
        { carrier: 'webtransport', reason: 'no_production_grade_node_quic_runtime' },
      ],
    });
    assert.equal(node.BROWSER_RUNTIME_CAPABILITY_V2, undefined);
    assert.deepEqual(browser.detectBrowserRuntimeCapabilityV2({
      WebSocket: function WebSocket() {},
      WebTransport: undefined,
    }).tuples.map(({ carrier }) => carrier).filter((value, index, all) => all.indexOf(value) === index), ['websocket']);
  `;

  run(process.execPath, ['--input-type=module', '-'], consumerDir, script);
}

function verifyEndpointTypes() {
  fs.writeFileSync(
    path.join(consumerDir, 'index.ts'),
    `import { Session, acceptDirect, acceptDirectResolved, connectTunnel } from '@floegence/flowersec-core/endpoint';
import type { DirectAcceptOptions, DirectCredentialResolver, EndpointOptions, EndpointStream, TunnelEndpointOptions } from '@floegence/flowersec-core/endpoint';

void Session;
void acceptDirect;
void acceptDirectResolved;
void connectTunnel;
const types: [DirectAcceptOptions?, DirectCredentialResolver?, EndpointOptions?, EndpointStream?, TunnelEndpointOptions?] = [];
void types;
`
  );
  fs.writeFileSync(
    path.join(consumerDir, 'tsconfig.json'),
    JSON.stringify({
      compilerOptions: {
        module: 'NodeNext',
        moduleResolution: 'NodeNext',
        noEmit: true,
        strict: true,
        target: 'ES2022',
      },
      include: ['*.ts'],
    }, null, 2)
  );
  run(process.execPath, [path.join(pkgRoot, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.json'], consumerDir);
}

function verifyArtifactOnlyConnectTypes() {
  fs.writeFileSync(
    path.join(consumerDir, 'artifact-only.ts'),
    `import { connect } from '@floegence/flowersec-core';
import { connectBrowser, requestConnectArtifact, requestEntryConnectArtifact } from '@floegence/flowersec-core/browser';
import { connectNode } from '@floegence/flowersec-core/node';
import type { ConnectArtifact } from '@floegence/flowersec-core';
import type { RequestConnectArtifactInput, RequestEntryConnectArtifactInput } from '@floegence/flowersec-core/browser';
// @ts-expect-error removed browser grant-request compatibility type.
import type { ControlplaneConfig as RemovedControlplaneConfig } from '@floegence/flowersec-core/browser';
// @ts-expect-error removed browser grant-request compatibility type.
import type { EntryControlplaneConfig as RemovedEntryControlplaneConfig } from '@floegence/flowersec-core/browser';
// @ts-expect-error removed browser artifact-request alias; use RequestConnectArtifactInput.
import type { ConnectArtifactRequestConfig as RemovedConnectArtifactRequestConfig } from '@floegence/flowersec-core/browser';
// @ts-expect-error removed browser artifact-request alias; use RequestEntryConnectArtifactInput.
import type { EntryConnectArtifactRequestConfig as RemovedEntryConnectArtifactRequestConfig } from '@floegence/flowersec-core/browser';

declare const artifact: ConnectArtifact;
void connect(artifact, { origin: 'https://app.example' });
void connectBrowser(artifact);
void connectNode(artifact, { origin: 'https://app.example' });
declare const artifactRequest: RequestConnectArtifactInput;
declare const entryArtifactRequest: RequestEntryConnectArtifactInput;
declare const removedTypes: [
  RemovedControlplaneConfig?,
  RemovedEntryControlplaneConfig?,
  RemovedConnectArtifactRequestConfig?,
  RemovedEntryConnectArtifactRequestConfig?,
];
void removedTypes;
void requestConnectArtifact(artifactRequest);
void requestEntryConnectArtifact(entryArtifactRequest);

const directInfo = {
  ws_url: 'wss://direct.example/ws',
  channel_id: 'channel',
  e2ee_psk_b64u: 'cHNr',
  channel_init_expire_at_unix_s: 1,
  default_suite: 1,
};
const tunnelGrant = {
  tunnel_url: 'wss://tunnel.example/ws',
  channel_id: 'channel',
  token: 'token',
  role: 1,
  e2ee_psk_b64u: 'cHNr',
  channel_init_expire_at_unix_s: 1,
  idle_timeout_seconds: 30,
  default_suite: 1,
  allowed_suites: [1],
};

// @ts-expect-error connect only accepts ConnectArtifact.
void connect(directInfo, { origin: 'https://app.example' });
// @ts-expect-error connect does not parse serialized inputs.
void connect(JSON.stringify(directInfo), { origin: 'https://app.example' });
// @ts-expect-error connect does not accept raw tunnel grants.
void connect(tunnelGrant, { origin: 'https://app.example' });
// @ts-expect-error connect does not accept grant wrappers.
void connect({ grant_client: tunnelGrant }, { origin: 'https://app.example' });
// @ts-expect-error connect does not accept controlplane response envelopes.
void connect({ connect_artifact: artifact }, { origin: 'https://app.example' });
// @ts-expect-error connectBrowser only accepts ConnectArtifact.
void connectBrowser(directInfo);
// @ts-expect-error connectBrowser does not accept raw tunnel grants.
void connectBrowser(tunnelGrant);
// @ts-expect-error connectNode only accepts ConnectArtifact.
void connectNode(directInfo, { origin: 'https://app.example' });
// @ts-expect-error connectNode does not accept raw tunnel grants.
void connectNode(tunnelGrant, { origin: 'https://app.example' });
`
  );
  run(process.execPath, [path.join(pkgRoot, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.json'], consumerDir);
}

function verifyTransportV2Types() {
  fs.writeFileSync(
    path.join(consumerDir, 'transport-v2.ts'),
    `import {
  createArtifactLeaseV2,
  createArtifactAcquireContextV2,
  createArtifactV2Resolver,
  createSessionReconnectManagerV2,
  decodeArtifactV2JSON,
  encodeArtifactV2JSON,
  FlowersecError,
  validateArtifactV2,
} from '@floegence/flowersec-core';
import {
  BROWSER_RUNTIME_CAPABILITY_V2,
  createArtifactLeaseV2 as createBrowserArtifactLeaseV2,
  decodeArtifactV2JSON as decodeBrowserArtifactV2JSON,
  FlowersecError as BrowserFlowersecError,
} from '@floegence/flowersec-core/browser';
import {
  NODE_RUNTIME_CAPABILITY_V2,
  createArtifactLeaseV2 as createNodeArtifactLeaseV2,
  decodeArtifactV2JSON as decodeNodeArtifactV2JSON,
  FlowersecError as NodeFlowersecError,
} from '@floegence/flowersec-core/node';
import type {
  BrowserSessionConnectorV2Options,
  JsonPrimitiveV2 as BrowserJsonPrimitiveV2,
  JsonValueV2 as BrowserJsonValueV2,
  NetworkModeV2 as BrowserNetworkModeV2,
  OperationOptionsV2 as BrowserOperationOptionsV2,
  SessionReconnectConfigV2 as BrowserSessionReconnectConfigV2,
  SessionRoleV2 as BrowserSessionRoleV2,
  SessionTerminationV2 as BrowserSessionTerminationV2,
  UnsupportedRuntimeCarrierV2 as BrowserUnsupportedRuntimeCarrierV2,
} from '@floegence/flowersec-core/browser';
// @ts-expect-error carrier SPI must remain package-internal.
import type { CarrierSessionV2 as BrowserCarrierSessionV2 } from '@floegence/flowersec-core/browser';
// @ts-expect-error native carrier SPI must remain package-internal.
import type { NativeCarrierSessionV2 as BrowserNativeCarrierSessionV2 } from '@floegence/flowersec-core/browser';
// @ts-expect-error carrier resource policy must remain package-internal.
import type { WebSocketResourcePolicyV2 as BrowserWebSocketResourcePolicyV2 } from '@floegence/flowersec-core/browser';
// @ts-expect-error candidate diagnostics must remain package-internal.
import type { FlowersecCandidateDiagnostic as BrowserFlowersecCandidateDiagnostic } from '@floegence/flowersec-core/browser';
// @ts-expect-error session key material and handshake configuration are package-internal.
import type { SessionConfigV2 as BrowserSessionConfigV2 } from '@floegence/flowersec-core/browser';
// @ts-expect-error low-level carrier attempt factories must remain package-internal.
import type { BrowserCandidateAttemptFactoryV2 } from '@floegence/flowersec-core/browser';
// @ts-expect-error low-level carrier attempts must remain package-internal.
import type { BrowserCandidateAttemptV2 } from '@floegence/flowersec-core/browser';
// @ts-expect-error prepared carrier candidates must remain package-internal.
import type { BrowserPreparedCandidateV2 } from '@floegence/flowersec-core/browser';
import type {
  JsonPrimitiveV2 as NodeJsonPrimitiveV2,
  JsonValueV2 as NodeJsonValueV2,
  NetworkModeV2 as NodeNetworkModeV2,
  OperationOptionsV2 as NodeOperationOptionsV2,
  SessionReconnectConfigV2 as NodeSessionReconnectConfigV2,
  SessionRoleV2 as NodeSessionRoleV2,
  SessionTerminationV2 as NodeSessionTerminationV2,
  UnsupportedRuntimeCarrierV2 as NodeUnsupportedRuntimeCarrierV2,
} from '@floegence/flowersec-core/node';
// @ts-expect-error carrier SPI must remain package-internal.
import type { CarrierSessionV2 as NodeCarrierSessionV2 } from '@floegence/flowersec-core/node';
// @ts-expect-error carrier resource policy must remain package-internal.
import type { WebSocketResourcePolicyV2 as NodeWebSocketResourcePolicyV2 } from '@floegence/flowersec-core/node';
// @ts-expect-error candidate diagnostics must remain package-internal.
import type { FlowersecCandidateDiagnostic as NodeFlowersecCandidateDiagnostic } from '@floegence/flowersec-core/node';
// @ts-expect-error session key material and handshake configuration are package-internal.
import type { SessionConfigV2 as NodeSessionConfigV2 } from '@floegence/flowersec-core/node';
import type {
  ArtifactAcquireContextV2,
  ArtifactLeaseV2,
  ArtifactSourceV2,
  ArtifactV2,
  ByteStreamV2,
  IncomingStreamV2,
  JsonObjectV2,
  PathKind,
  RuntimeCapabilityDescriptorV2,
  SessionReconnectConfigV2,
  SessionTerminationV2,
  SessionV2,
  StreamOpenOptionsV2,
} from '@floegence/flowersec-core';
// @ts-expect-error carrier SPI must remain package-internal.
import type { CarrierSessionV2, CarrierStreamV2 } from '@floegence/flowersec-core';
// @ts-expect-error native carrier SPI must remain package-internal.
import type { NativeCarrierSessionV2, NativeCarrierStreamV2 } from '@floegence/flowersec-core';
// @ts-expect-error WebSocket carrier SPI must remain package-internal.
import type { WebSocketBinaryTransportV2, WebSocketResourcePolicyV2 } from '@floegence/flowersec-core';
// @ts-expect-error candidate diagnostics must remain package-internal.
import type { FlowersecCandidateDiagnostic } from '@floegence/flowersec-core';
// @ts-expect-error session key material and handshake configuration are package-internal.
import type { SessionConfigV2 } from '@floegence/flowersec-core';
// @ts-expect-error implementation framing is not a public package subpath.
import type {} from '@floegence/flowersec-core/framing';
// @ts-expect-error the WebSocket Yamux implementation is package-internal.
import type {} from '@floegence/flowersec-core/yamux';
// @ts-expect-error transport crypto is package-internal.
import type {} from '@floegence/flowersec-core/e2ee';
// @ts-expect-error carrier adapters are package-internal.
import type {} from '@floegence/flowersec-core/ws';
// @ts-expect-error stream wire framing is package-internal.
import type {} from '@floegence/flowersec-core/streamhello';
// @ts-expect-error generated protocol modules are not public package subpaths.
import type {} from '@floegence/flowersec-core/gen/flowersec/rpc/v1';

declare const session: SessionV2;
declare const stream: ByteStreamV2;
declare const incoming: IncomingStreamV2;
declare const metadata: JsonObjectV2;
declare const openOptions: StreamOpenOptionsV2;
declare const rawArtifact: string;
declare const commitSpend: (signal?: AbortSignal) => Promise<void>;

const path: PathKind = session.path;
// @ts-expect-error selected carriers are internal diagnostics, not session API.
void session.chosenCarrier;
const browserDescriptor: RuntimeCapabilityDescriptorV2 = BROWSER_RUNTIME_CAPABILITY_V2;
const nodeDescriptor: RuntimeCapabilityDescriptorV2 = NODE_RUNTIME_CAPABILITY_V2;
const accepted: ByteStreamV2 = incoming.stream;
const artifact: ArtifactV2 = decodeArtifactV2JSON(rawArtifact);
const lease: ArtifactLeaseV2 = createArtifactLeaseV2(artifact, commitSpend);
const source: ArtifactSourceV2 = { kind: 'once', artifact, commitSpend };
const resolveArtifact = createArtifactV2Resolver(source);
const acquireContext: ArtifactAcquireContextV2 = createArtifactAcquireContextV2(
  browserDescriptor,
  { traceId: 'trace-1' },
);
const reconnectManager = createSessionReconnectManagerV2();
declare const reconnectConfig: SessionReconnectConfigV2;
declare const termination: SessionTerminationV2;
declare const browserTypes: readonly [BrowserJsonPrimitiveV2, BrowserJsonValueV2, BrowserNetworkModeV2, BrowserOperationOptionsV2, BrowserSessionReconnectConfigV2, BrowserSessionRoleV2, BrowserSessionTerminationV2, BrowserUnsupportedRuntimeCarrierV2];
declare const nodeTypes: readonly [NodeJsonPrimitiveV2, NodeJsonValueV2, NodeNetworkModeV2, NodeOperationOptionsV2, NodeSessionReconnectConfigV2, NodeSessionRoleV2, NodeSessionTerminationV2, NodeUnsupportedRuntimeCarrierV2];
const leakedWebSocketFactory: BrowserSessionConnectorV2Options = {
  admissionReasons: new Set(),
  // @ts-expect-error carrier construction factories must remain package-internal.
  webSocketFactory: () => { throw new Error('unreachable'); },
};
const leakedWebTransportFactory: BrowserSessionConnectorV2Options = {
  admissionReasons: new Set(),
  // @ts-expect-error carrier construction factories must remain package-internal.
  webTransportFactory: () => { throw new Error('unreachable'); },
};
const leakedAttemptFactory: BrowserSessionConnectorV2Options = {
  admissionReasons: new Set(),
  // @ts-expect-error low-level carrier attempt factories must remain package-internal.
  attemptFactory: { create: () => { throw new Error('unreachable'); } },
};

void path;
void FlowersecError;
void BrowserFlowersecError;
void NodeFlowersecError;
void browserDescriptor;
void nodeDescriptor;
void accepted;
void encodeArtifactV2JSON(artifact);
void validateArtifactV2(artifact);
void resolveArtifact(acquireContext);
void reconnectManager.connectIfNeeded(reconnectConfig);
void termination;
void browserTypes;
void nodeTypes;
void leakedWebSocketFactory;
void leakedWebTransportFactory;
void leakedAttemptFactory;
void createBrowserArtifactLeaseV2(decodeBrowserArtifactV2JSON(rawArtifact), commitSpend);
void createNodeArtifactLeaseV2(decodeNodeArtifactV2JSON(rawArtifact), commitSpend);
void lease.commitSpend();
void metadata;
void openOptions;
void stream.closeWrite();
void stream.reset();
void session.openStream('rpc', { metadata });

// @ts-expect-error v2 public streams must remain carrier-neutral.
void stream.yamuxStream;
// @ts-expect-error v2 public streams must remain carrier-neutral.
void stream.quicStream;
// @ts-expect-error v2 public sessions do not expose the v1 mux implementation.
void session.mux;
`
  );
  run(process.execPath, [path.join(pkgRoot, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.json'], consumerDir);
}

try {
  verifyPackageJSONExports();
  const tarballName = packTarball();
  const tarballPath = path.join(packDir, tarballName);
  assert.equal(fs.existsSync(tarballPath), true, 'packed tarball must exist');
  installTarball(tarballPath);
  verifyBrowserDependencyGraph();
  verifyInstalledPackage();
  verifyEndpointTypes();
  verifyArtifactOnlyConnectTypes();
  verifyTransportV2Types();
} finally {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
}
