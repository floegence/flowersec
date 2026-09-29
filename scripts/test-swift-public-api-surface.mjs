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
  'ConnectionMaterialOwner',
  'TransportEnvironmentOwner',
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
assert.equal(rendered.includes('ArtifactError'), true, 'Swift public API must expose ArtifactError');
assert.equal(rendered.includes('invalidValue'), true, 'Swift metadata errors must expose invalidValue');
for (const [name, fragments] of [
  ['TransportEnvironment.init(configuration:)', ['TransportV4ClientConfiguration', 'async throws']],
  ['TransportEnvironment.preparePoolMaterial(_:identity:)', ['TransportV4PoolCredential', 'TransportV4ApplicationIdentity', 'throws -> ConnectionMaterial']],
  ['TransportEnvironment.connectMaterial(_:requirements:)', ['ConnectionMaterial', 'ConnectionRequirements', 'async throws -> any Session']],
  ['TransportEnvironment.connect(source:requirements:)', ['any ConnectionMaterialSource', 'ConnectionRequirements', 'async throws -> any Session']],
  ['TransportEnvironment.generateApplicationIdentity(profile:)', ['TransportV4CryptoProfile', 'TransportV4ApplicationIdentity']],
  ['TransportEnvironment.importApplicationIdentity(profile:signingSeed:noiseStaticPrivateKey:)', ['TransportV4CryptoProfile', 'Data', 'TransportV4ApplicationIdentity']],
  ['TransportEnvironment.refreshTrustedTime()', ['throws']],
  ['TransportEnvironment.refreshNamespace(authority:head:state:)', ['String', 'Data', 'throws']],
  ['TransportEnvironment.invalidateTimeContinuity()', []],
  ['ConnectionMaterial.waitCleanup()', ['async throws -> CleanupStatus']],
  ['StreamMetadata.init(namespace:version:values:)', ['String', 'UInt16', '[String : Data]', 'throws']],
  ['StreamMetadata.init(encodedV4:)', ['Data', 'throws']],
  ['StreamMetadata.encodedV4()', ['throws -> Data']],
  ['StreamMetadata.v4Namespace', ['String?']],
  ['StreamMetadata.v4Version', ['UInt16?']],
  ['StreamMetadata.v4Values', ['[String : Data]?']],
]) {
  assert.equal(surface.some(({ pathComponents, declaration }) =>
    pathComponents.join('.') === name && fragments.every((fragment) => declaration.includes(fragment))),
  true, `Swift v4 public signature missing or changed: ${name}`);
}
for (const opaque of ['ConnectionMaterial', 'TransportV4ApplicationIdentity', 'ReaderCursor',
  'WriteOperation', 'NotificationSubscription', 'OperationHandle']) {
  assert.equal(surface.some(({ pathComponents }) => pathComponents[0] === opaque
    && (pathComponents[1]?.startsWith('init(') || pathComponents[1] === 'owner')),
  false, `${opaque} must retain its original SDK owner`);
}
assert.equal(
  rendered.includes('RPCNotificationError'),
  true,
  'Swift public API must expose typed notification decode failures',
);
assert.equal(
  surface.some(({ pathComponents, declaration }) =>
    pathComponents.join('.') === 'RPCPeer.subscribeNotification(_:as:handler:)'
      && declaration.includes('Result<Payload, RPCNotificationError>')
      && declaration.includes('async throws -> any RPCNotificationSubscription')),
  true,
  'Swift RPCPeer must expose deterministic typed notification subscriptions',
);
assert.equal(
  surface.some(({ pathComponents, declaration }) =>
    pathComponents.join('.') === 'RPCNotificationSubscription.cancel()'
      && declaration.includes('async')),
  true,
  'Swift notification subscriptions must expose async cancellation',
);
