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
  'maxEncodedBytes',
  'maxDepth',
  'maxNodes',
  'maxObjectKeys',
  'maxArrayItems',
  'maxKeyBytes',
  'maxStringBytes',
  'maximumSafeInteger',
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
