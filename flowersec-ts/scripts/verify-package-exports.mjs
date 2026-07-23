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
const artifactFixture = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'testdata', 'transport_v2', 'artifact_vectors.json'), 'utf8')
).positive[0].artifact_json;
const forbiddenRuntimeExportsBySubpath = new Map([
  ['@floegence/flowersec-core/proxy', ['resolveNamedProxyPreset', 'CODESERVER_PROXY_PRESET_MANIFEST']],
]);
const removedLegacyRuntimeExports = new Set([
  'connect', 'connectTunnel', 'connectDirect',
  'assertChannelInitGrant', 'assertDirectConnectInfo', 'assertConnectArtifact',
  'connectBrowser', 'connectTunnelBrowser', 'connectDirectBrowser',
  'requestConnectArtifact', 'requestEntryConnectArtifact',
  'createBrowserReconnectConfig', 'createTunnelBrowserReconnectConfig', 'createDirectBrowserReconnectConfig',
  'connectNode', 'connectTunnelNode', 'connectDirectNode', 'createNodeWsFactory',
  'createNodeReconnectConfig', 'createTunnelNodeReconnectConfig', 'createDirectNodeReconnectConfig',
  'BrowserSessionConnectorV2',
  'requestChannelGrant',
  'requestEntryChannelGrant',
  'establishSessionV2',
  'AdmissionSessionV2Error',
  'establishAdmittedNativeSessionV2',
  'establishAdmittedWebSocketSessionV2',
  'ArtifactV2Error',
  'decodeArtifactV2JSON',
  'encodeArtifactV2JSON',
  'validateArtifactV2',
  'BROWSER_RUNTIME_CAPABILITY_V2',
  'NODE_RUNTIME_CAPABILITY_V2',
  'decodeRuntimeCapabilityDescriptorV2',
  'detectBrowserRuntimeCapabilityV2',
  'encodeRuntimeCapabilityDescriptorV2',
  'runtimeCapabilityDigestHexV2',
  'runtimeCapabilityDigestV2',
  'validateRuntimeCapabilityDescriptorV2',
  'FlowersecError',
  'SessionV2',
]);
const v2OnlyEntrypoints = new Set([
  '@floegence/flowersec-core',
  '@floegence/flowersec-core/browser',
  '@floegence/flowersec-core/node',
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
  'v2/artifact',
  'v2/protocol',
  'v2/session',
  'browser/connectV2',
  'node/connectV2',
  'utils/errors',
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
    for (const exportName of subpath.runtime_exports.filter((name) => !removedLegacyRuntimeExports.has(name))) {
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
    for (const exportName of v2OnlyEntrypoints.has(subpath.specifier) ? removedLegacyRuntimeExports : []) {
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

    const browser = await import('@floegence/flowersec-core/browser');
    const root = await import('@floegence/flowersec-core');
    assert.equal(root.ConnectError, browser.ConnectError);
    const redacted = new root.ConnectError('connection_failed');
    assert.deepEqual(
      { name: redacted.name, code: redacted.code },
      { name: 'ConnectError', code: 'connection_failed' },
    );
    assert.equal('path' in redacted, false);
    assert.equal('stage' in redacted, false);
    assert.equal('diagnostics' in redacted, false);
    assert.equal('candidateId' in redacted, false);
    assert.equal('carrier' in redacted, false);
    assert.equal('cause' in redacted, false);
    const artifact = root.parseArtifact(${JSON.stringify(artifactFixture)});
    assert.deepEqual(Object.keys(artifact), []);
    assert.equal(JSON.stringify(artifact), '{}');
    assert.throws(() => root.createArtifactLeaseV2({}, async () => {}), /invalid Flowersec artifact handle/);
    assert.equal(root.createArtifactLeaseV2(artifact, async () => {}).artifact, artifact);
    assert.equal(Object.prototype.hasOwnProperty.call(browser, 'requestConnectArtifact'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(browser, 'requestEntryConnectArtifact'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(browser, 'createBrowserWebTransportCarrierInternalStage'), false);
    assert.equal(browser.BROWSER_RUNTIME_CAPABILITY_V2, undefined);
    assert.equal(browser.NODE_RUNTIME_CAPABILITY_V2, undefined);
    assert.equal(browser.detectBrowserRuntimeCapabilityV2, undefined);
    assert.equal(browser.runtimeCapabilityDigestHexV2, undefined);

    const node = await import('@floegence/flowersec-core/node');
    assert.equal(node.NODE_RUNTIME_CAPABILITY_V2, undefined);
    assert.equal(node.BROWSER_RUNTIME_CAPABILITY_V2, undefined);
    assert.equal(root.BROWSER_RUNTIME_CAPABILITY_V2, undefined);
    assert.equal(root.NODE_RUNTIME_CAPABILITY_V2, undefined);
  `;

  run(process.execPath, ['--input-type=module', '-'], consumerDir, script);
}

function verifyArtifactOnlyConnectTypes() {
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
  fs.writeFileSync(
    path.join(consumerDir, 'artifact-only.ts'),
    `// @ts-expect-error Transport v1 root connect is removed.
import { connect, connectDirect, connectTunnel } from '@floegence/flowersec-core';
// @ts-expect-error raw Transport v1 artifacts are removed.
import type { ConnectArtifact } from '@floegence/flowersec-core';
// @ts-expect-error Transport v1 browser connects are removed.
import { connectBrowser, connectDirectBrowser, connectTunnelBrowser } from '@floegence/flowersec-core/browser';
// @ts-expect-error Transport v1 controlplane artifact requests are removed.
import { requestConnectArtifact, requestEntryConnectArtifact } from '@floegence/flowersec-core/browser';
// @ts-expect-error Transport v1 Node connects are removed.
import { connectNode, connectDirectNode, connectTunnelNode } from '@floegence/flowersec-core/node';
void [connect, connectDirect, connectTunnel, connectBrowser, connectDirectBrowser, connectTunnelBrowser,
  requestConnectArtifact, requestEntryConnectArtifact, connectNode, connectDirectNode, connectTunnelNode];
type Removed = ConnectArtifact;
declare const removed: Removed;
void removed;
`
  );
  run(process.execPath, [path.join(pkgRoot, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.json'], consumerDir);
}

function verifyTransportV2Types() {
  fs.writeFileSync(
    path.join(consumerDir, 'transport-v2.ts'),
    `import {
  Artifact,
  createArtifactLeaseV2,
  createArtifactAcquireContextV2,
  createArtifactV2Resolver,
  createSessionReconnectManagerV2,
  ConnectError,
  parseArtifact,
} from '@floegence/flowersec-core';
import {
  createArtifactLeaseV2 as createBrowserArtifactLeaseV2,
  ConnectError as BrowserConnectError,
} from '@floegence/flowersec-core/browser';
import {
  createArtifactLeaseV2 as createNodeArtifactLeaseV2,
  ConnectError as NodeConnectError,
} from '@floegence/flowersec-core/node';
import type {
  BrowserSessionConnectorV2Options,
  JsonPrimitiveV2 as BrowserJsonPrimitiveV2,
  JsonValueV2 as BrowserJsonValueV2,
  OperationOptionsV2 as BrowserOperationOptionsV2,
  SessionReconnectConfigV2 as BrowserSessionReconnectConfigV2,
  SessionError as BrowserSessionError,
  SessionTerminationV2 as BrowserSessionTerminationV2,
} from '@floegence/flowersec-core/browser';
// @ts-expect-error capability descriptors are runtime-internal.
import type { RuntimeCapabilityDescriptorV2 as BrowserRuntimeCapabilityDescriptorV2 } from '@floegence/flowersec-core/browser';
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
  NodeSessionConnectorV2Options,
  OperationOptionsV2 as NodeOperationOptionsV2,
  SessionReconnectConfigV2 as NodeSessionReconnectConfigV2,
  SessionError as NodeSessionError,
  SessionTerminationV2 as NodeSessionTerminationV2,
} from '@floegence/flowersec-core/node';
// @ts-expect-error capability descriptors are runtime-internal.
import type { RuntimeCapabilityDescriptorV2 as NodeRuntimeCapabilityDescriptorV2 } from '@floegence/flowersec-core/node';
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
  ByteStreamV2,
  IncomingStreamV2,
  JsonObjectV2,
  SessionError,
  SessionReconnectConfigV2,
  SessionTerminationV2,
  SessionV2,
  StreamOpenOptionsV2,
} from '@floegence/flowersec-core';
// @ts-expect-error capability descriptors are runtime-internal.
import type { RuntimeCapabilityDescriptorV2 } from '@floegence/flowersec-core';
// @ts-expect-error raw artifacts must remain package-internal.
import type { ArtifactV2 } from '@floegence/flowersec-core';
// @ts-expect-error candidate details must remain package-internal.
import type { ArtifactCandidateV2, CanonicalArtifactCandidateV2 } from '@floegence/flowersec-core';
// @ts-expect-error session wire contracts must remain package-internal.
import type { SessionContractV2 } from '@floegence/flowersec-core';
// @ts-expect-error carrier SPI must remain package-internal.
import type { CarrierSessionV2, CarrierStreamV2 } from '@floegence/flowersec-core';
// @ts-expect-error native carrier SPI must remain package-internal.
import type { NativeCarrierSessionV2, NativeCarrierStreamV2 } from '@floegence/flowersec-core';
// @ts-expect-error WebSocket carrier SPI must remain package-internal.
import type { WebSocketBinaryTransportV2, WebSocketResourcePolicyV2 } from '@floegence/flowersec-core';
// @ts-expect-error candidate diagnostics must remain package-internal.
import type { FlowersecCandidateDiagnostic } from '@floegence/flowersec-core';
// @ts-expect-error raw artifact input aliases must remain package-internal.
import type { ArtifactInputV2, ArtifactDecoderV2 } from '@floegence/flowersec-core';
// @ts-expect-error the previous diagnostic-bearing error is removed.
import { FlowersecError } from '@floegence/flowersec-core';
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

const artifact = parseArtifact(rawArtifact);
Object.keys(artifact);
JSON.stringify(artifact);
// @ts-expect-error opaque artifacts do not expose path selection.
void artifact.path;
// @ts-expect-error opaque artifacts do not expose session wire details.
void artifact.session;
// @ts-expect-error opaque artifacts cannot be constructed by consumers.
new Artifact();
// @ts-expect-error plain objects cannot forge opaque artifact handles.
const forgedArtifact: Artifact = {};
void forgedArtifact;

// @ts-expect-error path selection is internal to the opaque session.
void session.path;
// @ts-expect-error peer endpoint identity is internal to the opaque session.
void session.endpointInstanceId;
// @ts-expect-error selected carriers are internal diagnostics, not session API.
void session.chosenCarrier;
// @ts-expect-error logical stream IDs are internal wire bookkeeping.
void stream.id;
// @ts-expect-error incoming logical stream IDs are internal wire bookkeeping.
void incoming.id;
const accepted: ByteStreamV2 = incoming.stream;
const lease: ArtifactLeaseV2 = createArtifactLeaseV2(artifact, commitSpend);
const source: ArtifactSourceV2 = { kind: 'once', artifact, commitSpend };
// @ts-expect-error lease construction accepts opaque Artifact handles only.
createArtifactLeaseV2(rawArtifact, commitSpend);
// @ts-expect-error one-time sources accept opaque Artifact handles only.
const rawSource: ArtifactSourceV2 = { kind: 'once', artifact: rawArtifact, commitSpend };
const resolveArtifact = createArtifactV2Resolver(source);
const acquireContext: ArtifactAcquireContextV2 = createArtifactAcquireContextV2({ traceId: 'trace-1' });
const reconnectManager = createSessionReconnectManagerV2();
declare const reconnectConfig: SessionReconnectConfigV2;
declare const termination: SessionTerminationV2;
declare const browserTypes: readonly [BrowserJsonPrimitiveV2, BrowserJsonValueV2, BrowserOperationOptionsV2, BrowserSessionReconnectConfigV2, BrowserSessionTerminationV2, BrowserSessionError, BrowserRuntimeCapabilityDescriptorV2];
declare const nodeTypes: readonly [NodeJsonPrimitiveV2, NodeJsonValueV2, NodeOperationOptionsV2, NodeSessionReconnectConfigV2, NodeSessionTerminationV2, NodeSessionError, NodeRuntimeCapabilityDescriptorV2];
const leakedWebSocketFactory: BrowserSessionConnectorV2Options = {
  // @ts-expect-error admission policy is runtime-owned.
  admissionReasons: new Set(),
};
const leakedWebTransportFactory: BrowserSessionConnectorV2Options = {
  // @ts-expect-error carrier construction factories must remain package-internal.
  webTransportFactory: () => { throw new Error('unreachable'); },
};
const leakedAttemptFactory: BrowserSessionConnectorV2Options = {
  // @ts-expect-error low-level carrier attempt factories must remain package-internal.
  attemptFactory: { create: () => { throw new Error('unreachable'); } },
};
const leakedNodeCarrierOptions: NodeSessionConnectorV2Options = {
  origin: 'https://app.example',
  // @ts-expect-error Node carrier-specific tuning is package-internal.
  webSocket: {},
};
declare const terminalError: SessionError;
const connectError = new ConnectError('connection_failed');
// @ts-expect-error public connection errors expose only their closed code.
void connectError.path;
// @ts-expect-error public connection errors expose only their closed code.
void connectError.stage;

void ConnectError;
void BrowserConnectError;
void NodeConnectError;
void FlowersecError;
void rawSource;
void (undefined as unknown as RuntimeCapabilityDescriptorV2);
void accepted;
void resolveArtifact(acquireContext);
void reconnectManager.connectIfNeeded(reconnectConfig);
void termination;
void browserTypes;
void nodeTypes;
void leakedWebSocketFactory;
void leakedWebTransportFactory;
void leakedAttemptFactory;
void leakedNodeCarrierOptions;
void terminalError;
void createBrowserArtifactLeaseV2(artifact, commitSpend);
void createNodeArtifactLeaseV2(artifact, commitSpend);
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
  verifyArtifactOnlyConnectTypes();
  verifyTransportV2Types();
} finally {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
}
