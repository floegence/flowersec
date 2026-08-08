import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
execFileSync(
  'swift',
  ['package', 'dump-symbol-graph', '--minimum-access-level', 'public'],
  { cwd: root, stdio: 'pipe' },
);

const graphPath = findFile(path.join(root, '.build'), 'Flowersec.symbols.json');
assert.notEqual(graphPath, undefined, 'Swift package did not produce the Flowersec symbol graph');
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

function findFile(directory, name) {
  if (!fs.existsSync(directory)) return undefined;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      const found = findFile(target, name);
      if (found !== undefined) return found;
    } else if (entry.name === name) {
      return target;
    }
  }
  return undefined;
}
