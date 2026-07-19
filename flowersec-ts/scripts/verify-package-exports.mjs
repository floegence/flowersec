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
const removedLegacyRuntimeExports = new Set(['requestChannelGrant', 'requestEntryChannelGrant']);

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

    const reconnect = await import('@floegence/flowersec-core/reconnect');
    const mgr = reconnect.createReconnectManager();
    assert.equal(typeof mgr.connectIfNeeded, 'function');

    const browser = await import('@floegence/flowersec-core/browser');
    assert.equal(typeof browser.requestConnectArtifact, 'function');
    assert.equal(typeof browser.requestEntryConnectArtifact, 'function');
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

try {
  verifyPackageJSONExports();
  const tarballName = packTarball();
  const tarballPath = path.join(packDir, tarballName);
  assert.equal(fs.existsSync(tarballPath), true, 'packed tarball must exist');
  installTarball(tarballPath);
  verifyInstalledPackage();
  verifyEndpointTypes();
  verifyArtifactOnlyConnectTypes();
} finally {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
}
