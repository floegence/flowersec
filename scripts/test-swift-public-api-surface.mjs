import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const reuseVerifiedGraph = process.argv[2] === '--reuse-verified-graph';
assert.equal(
  process.argv.length,
  reuseVerifiedGraph ? 3 : 2,
  'usage: test-swift-public-api-surface.mjs [--reuse-verified-graph]',
);
if (!reuseVerifiedGraph) {
  execFileSync('go', ['run', '.', 'verify-swift'], {
    cwd: path.join(root, 'tools', 'stabilitycheck'),
    stdio: 'inherit',
  });
}

const graphPath = path.join(root, '.build', 'stability-symbolgraph', 'Flowersec.symbols.json');
assert.equal(fs.existsSync(graphPath), true, 'Swift stability verifier did not produce the Flowersec symbol graph');
const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
const surface = graph.symbols.map((symbol) => ({
  title: symbol.names?.title ?? '',
  pathComponents: symbol.pathComponents ?? [],
  declaration: (symbol.declarationFragments ?? []).map((fragment) => fragment.spelling).join(''),
}));
const rendered = surface
  .map(({ title, pathComponents, declaration }) =>
    `${pathComponents.join('.')}\n${title}\n${declaration}`)
  .join('\n');

for (const forbidden of [
  'ArtifactCodecError',
  'maximumAttemptsReached',
  'encodedByteCount',
  'maxDepth',
  'maxNodes',
  'maxObjectKeys',
  'maxArrayItems',
  'maxKeyBytes',
  'maxStringBytes',
  'maximumSafeInteger',
  'V4ClientEnvironment',
  'V4CredentialAdmission',
  'V4DirectPoolMaterial',
  'V4NativeSessionAdmission',
  'V4PinnedTLS',
  'V4StreamMetadataProjection',
  'V4StreamMetadataCodec',
  'V4ContractAcceptance',
  'V4ContractRange',
  'V4ContractRangeField',
  'V4ContractPolicyFailure',
  'ConnectionMaterialOwner',
  'TransportEnvironmentOwner',
  'TransportV4',
  'transportv4',
  'transport_v4',
  'encodedV4',
  'v4Namespace',
  'v4Version',
  'v4Values',
  'RPCPeer',
  'RPCNotificationError',
  'RPCNotificationSubscription',
]) {
  assert.equal(rendered.includes(forbidden), false, `Swift public API leaked ${forbidden}`);
}
assert.equal(
  surface.some(({ pathComponents }) =>
    pathComponents.length === 2
      && pathComponents[0] === 'ArtifactLease'
      && pathComponents[1] === 'artifact'),
  false,
  'ArtifactLease must not expose its artifact',
);
// The current public contract reports malformed/unsupported material through
// ConnectError and its bounded projections; the old ArtifactError name was
// removed with the pre-v4 Artifact wrapper and must not be reintroduced.
assert.equal(rendered.includes('ConnectError'), true, 'Swift public API must expose ConnectError');
assert.equal(rendered.includes('invalidValue'), true, 'Swift metadata errors must expose invalidValue');
for (const [name, fragments] of [
  ['TransportEnvironment.init(configuration:)', ['TransportClientConfiguration', 'async throws']],
  ['TransportEnvironment.preparePoolMaterial(_:identity:role:)', ['TransportPoolCredential', 'TransportApplicationIdentity', 'ConnectionEndpointRole', 'throws -> ConnectionMaterial']],
  ['TransportEnvironment.connectMaterial(_:requirements:)', ['ConnectionMaterial', 'ConnectionRequirements', 'async throws -> any Session']],
  ['TransportEnvironment.connect(source:requirements:)', ['ConnectionMaterialSource', 'ConnectionRequirements', 'async throws -> any Session']],
  ['TransportEnvironment.generateApplicationIdentity(profile:)', ['TransportCryptoProfile', 'TransportApplicationIdentity']],
  ['TransportEnvironment.importApplicationIdentity(profile:signingSeed:noiseStaticPrivateKey:)', ['TransportCryptoProfile', 'Data', 'TransportApplicationIdentity']],
  ['TransportEnvironment.refreshTrustedTime()', ['throws']],
  ['TransportEnvironment.refreshNamespace(authority:head:state:)', ['String', 'Data', 'throws']],
  ['TransportEnvironment.invalidateTimeContinuity()', []],
  ['ConnectionMaterial.waitCleanup()', ['async throws -> CleanupStatus']],
  ['StreamMetadata.init(namespace:version:values:)', ['String', 'UInt16', '[String : Data]', 'throws']],
  ['StreamMetadata.init(encoded:)', ['Data', 'throws']],
  ['StreamMetadata.encoded()', ['throws -> Data']],
  ['StreamMetadata.namespace', ['String?']],
  ['StreamMetadata.version', ['UInt16?']],
  ['StreamMetadata.values', ['[String : JSONValue]']],
  ['StreamMetadata.byteValues', ['[String : Data]?']],
]) {
  assert.equal(surface.some(({ pathComponents, declaration }) =>
    pathComponents.join('.') === name && fragments.every((fragment) => declaration.includes(fragment))),
  true, `Swift v4 public signature missing or changed: ${name}`);
}
for (const opaque of ['ConnectionMaterial', 'TransportApplicationIdentity', 'ReaderCursor',
  'WriteOperation', 'ServiceNotificationSubscription', 'OperationHandle']) {
  assert.equal(surface.some(({ pathComponents }) => pathComponents[0] === opaque
    && (pathComponents[1]?.startsWith('init(') || pathComponents[1] === 'owner')),
  false, `${opaque} must retain its original SDK owner`);
}
assert.equal(
  surface.some(({ pathComponents, declaration }) =>
    pathComponents.join('.') === 'ServiceClient.subscribe(_:codec:options:context:handler:)'
      && declaration.includes('MessageCodec<Value>')
      && declaration.includes('async throws -> ServiceNotificationSubscription<Value>')),
  true,
  'Swift service clients must expose original typed notification subscriptions',
);
assert.equal(
  surface.some(({ pathComponents, declaration }) =>
    pathComponents.join('.') === 'ServiceNotificationSubscription.waitClosed(_:)'
      && declaration.includes('NotificationWaitOptions')
      && declaration.includes('async throws -> CleanupStatus')),
  true,
  'Swift notification subscriptions must expose original cleanup observation',
);
assert.equal(surface.some(({ pathComponents }) => pathComponents.join('.') === 'NotificationGap.decodeError'),
  true, 'Swift notification observations must expose decode failures');
