import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs';
import { createServer } from 'node:net';
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
  fs.readFileSync(path.join(repoRoot, 'testdata', 'transport_v3', 'artifact_vectors.json'), 'utf8')
).positive[0].artifact_json;
const rejectedArtifactFixture = JSON.stringify({ v: 2, profile: 'flowersec/2' });
const forbiddenRuntimeExportsBySubpath = new Map([
  ['@floegence/flowersec-core/proxy', [
    'resolveNamedProxyPreset', 'CODESERVER_PROXY_PRESET_MANIFEST',
    'assertProxyRuntimeScopeV1', 'connectArtifactProxyBrowser', 'connectArtifactProxyControllerBrowser',
    'parseAppProxyFetchMessage', 'parseRuntimeRequest', 'RuntimeFetchMessage',
    'Client', 'YamuxSession',
  ]],
]);
const removedRuntimeExports = new Set([
  'connectTunnel', 'connectDirect',
  'assertChannelInitGrant', 'assertDirectConnectInfo', 'assertConnectArtifact',
  'connectBrowser', 'connectTunnelBrowser', 'connectDirectBrowser',
  'requestConnectArtifact', 'requestEntryConnectArtifact',
  'createBrowserReconnectConfig', 'createTunnelBrowserReconnectConfig', 'createDirectBrowserReconnectConfig',
  'connectNode', 'connectTunnelNode', 'connectDirectNode', 'createNodeWsFactory',
  'createNodeReconnectConfig', 'createTunnelNodeReconnectConfig', 'createDirectNodeReconnectConfig',
  'requestChannelGrant',
  'requestEntryChannelGrant',
  'FlowersecError',
  'connectV3', 'createConnectionControllerV3', 'createArtifactLeaseV3', 'parseArtifactV3',
  'createAcceptorV3', 'createTunnelRuntimeV3', 'verifyTunnelAuthorizationGrantV3',
  'v2',
]);
const removedImplementationSubpaths = [
  'framing',
  'yamux',
  'e2ee',
  'ws',
  'streamhello',
  'client',
  'endpoint',
  'endpoint/serve',
  'origin',
  'proxy/runtime',
  'rpc',
  'stream',
  'protocolio',
  'gen/flowersec/controlplane/v1',
  'gen/flowersec/direct/v1',
  'gen/flowersec/e2ee/v1',
  'gen/flowersec/rpc/v1',
  'gen/flowersec/tunnel/v1',
  'v2',
  'v2/artifact',
  'v2/protocol',
  'v2/session',
  'v3',
  'browser/connectSession',
  'node/connectSession',
  'public/contract',
  'public/artifact',
  'public/artifactLease',
  'public/streamMetadata',
  'connector/sessionConnector',
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

function verifyInstalledDeclarationClosure() {
  const installedRoot = path.join(consumerDir, 'node_modules', '@floegence', 'flowersec-core');
  const installedPackage = JSON.parse(fs.readFileSync(path.join(installedRoot, 'package.json'), 'utf8'));
  const entrypoints = Object.values(installedPackage.exports).map((entry) => path.join(installedRoot, entry.types));
  const pending = [...entrypoints];
  const visited = new Set();
  const sources = [];
  while (pending.length > 0) {
    const file = pending.pop();
    if (visited.has(file)) continue;
    assert.equal(fs.existsSync(file), true, `missing exported declaration ${path.relative(installedRoot, file)}`);
    visited.add(file);
    const source = fs.readFileSync(file, 'utf8');
    sources.push(source);
    const imports = source.matchAll(/(?:from\s+|import\s*)["']([^"']+)["']/gu);
    for (const imported of imports) {
      if (!imported[1].startsWith('.')) continue;
      const resolved = path.resolve(path.dirname(file), imported[1]);
      const candidates = [resolved.replace(/\.js$/, '.d.ts'), `${resolved}.d.ts`, resolved];
      const dependency = candidates.find((candidate) => fs.existsSync(candidate));
      assert.notEqual(dependency, undefined, `unresolvable declaration import ${imported[1]} from ${file}`);
      assert.equal(dependency.startsWith(`${installedRoot}${path.sep}`), true, 'declaration closure escaped the installed package');
      pending.push(dependency);
    }
  }
  const publicDeclarations = sources.join('\n');
  assert.doesNotMatch(
    publicDeclarations,
    /(?:^|["'\/])connector(?:["'\/]|\.)/u,
    'exported declaration closure referenced an internal module',
  );
  assert.doesNotMatch(
    publicDeclarations,
    /(?:^|["'\/])utils\/errors(?:["'\/]|\.)/u,
    'exported declaration closure referenced internal error implementation',
  );
  assert.doesNotMatch(
    publicDeclarations,
    /LegacyUnreliableSessionErrorCode|absoluteUnixMilliseconds|responseFlowControl|flowersec-proxy:|response_flow_control/u,
    'exported declarations leaked removed compatibility or private Service Worker protocol fields',
  );
}

function verifyInstalledPackage() {
  const checks = manifest.ts.subpaths.map((subpath, index) => {
    const moduleVar = `mod${index}`;
    const lines = [
      `    const ${moduleVar} = await import(${JSON.stringify(subpath.specifier)});`
    ];
    lines.push(
      `    assert.deepEqual(Object.keys(${moduleVar}).sort(), ${JSON.stringify([...subpath.runtime_exports].sort())}, ${JSON.stringify(subpath.specifier + ' runtime export set drifted from the API contract manifest')});`
    );
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
    for (const exportName of removedRuntimeExports) {
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
    const redacted = new root.ConnectError('connection_failed', { kind: 'terminal' });
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
    assert.equal('disposition' in redacted, false);
    assert.deepEqual(redacted.retryDisposition, { kind: 'terminal' });
    const artifact = root.parseArtifact(${JSON.stringify(artifactFixture)});
    assert.deepEqual(Object.keys(artifact), []);
    assert.equal(JSON.stringify(artifact), '{}');
    assert.throws(
      () => root.createArtifactLease({}, async () => {}),
      (error) => error?.name === 'ArtifactError' && error?.code === 'invalid_artifact',
    );
    assert.equal(
      Object.prototype.hasOwnProperty.call(root.createArtifactLease(artifact, async () => {}), 'artifact'),
      false,
      'ArtifactLease must not expose its artifact',
    );
    assert.throws(
      () => root.parseArtifact(${JSON.stringify(rejectedArtifactFixture)}),
      (error) => error?.name === 'ArtifactError' && error?.code === 'invalid_artifact',
    );
    assert.equal(Object.prototype.hasOwnProperty.call(browser, 'requestConnectArtifact'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(browser, 'requestEntryConnectArtifact'), false);

    const node = await import('@floegence/flowersec-core/node');
    assert.equal(typeof node.ProxyServer, 'function');
    assert.equal(typeof node.ProxyServerError, 'function');
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
  run(process.execPath, [path.join(pkgRoot, 'node_modules', 'typescript', 'bin', 'tsc6'), '-p', 'tsconfig.json'], consumerDir);
}

function verifyCurrentTypes() {
  fs.writeFileSync(
    path.join(consumerDir, 'current-api.ts'),
    `import {
  Artifact,
  ArtifactLease,
  ByteStream,
  ConnectError,
  ConnectionController,
  Session,
  StreamMetadata,
  createArtifactLease,
  createStreamMetadata,
  parseArtifact,
} from '@floegence/flowersec-core';
import {
  ProxyServer,
  ProxyServerError,
  connect,
  createAcceptor,
  createConnectionController,
} from '@floegence/flowersec-core/node';
import type {
  ProxyServerOptions,
  SessionOptions,
} from '@floegence/flowersec-core/node';
// @ts-expect-error versioned namespaces and aliases are not public in Flowersec 4.
import { v2, parseArtifactV3 } from '@floegence/flowersec-core';

declare const rawArtifact: string;
declare const session: Session;
declare const stream: ByteStream;
declare const options: SessionOptions;
declare const proxyOptions: ProxyServerOptions;
const artifact: Artifact = parseArtifact(rawArtifact);
const lease: ArtifactLease = createArtifactLease(artifact, async () => undefined);
const metadata: StreamMetadata = createStreamMetadata({ purpose: 'package-check' });
const controller: ConnectionController = createConnectionController({
  acquire: async () => ({ kind: 'lease', lease }),
}, options);
void connect(lease, options);
void createAcceptor;
void new ProxyServer(proxyOptions);
void ProxyServerError;
void ConnectError;
void controller;
void metadata;
void stream.closeWrite();
void stream.reset();
void v2;
void parseArtifactV3;
`
  );
  run(process.execPath, [path.join(pkgRoot, 'node_modules', 'typescript', 'bin', 'tsc6'), '-p', 'tsconfig.json'], consumerDir);
}

async function verifyPackedBin() {
  const installedRoot = path.join(consumerDir, 'node_modules', '@floegence', 'flowersec-core');
  const installedPackage = JSON.parse(fs.readFileSync(path.join(installedRoot, 'package.json'), 'utf8'));
  assert.deepEqual(installedPackage.bin, { 'flowersec-ts-cli': './dist/cli.js' });
  const cliPath = path.join(installedRoot, 'dist', 'cli.js');
  const cli = fs.readFileSync(cliPath, 'utf8');
  assert.equal(cli.startsWith('#!/usr/bin/env node\n'), true, 'CLI must retain its Node shebang');
  assert.equal((fs.statSync(cliPath).mode & 0o111) !== 0, true, 'CLI must be executable');
  const rejected = path.join(consumerDir, 'rejected-artifact.json');
  fs.writeFileSync(rejected, rejectedArtifactFixture);
  for (const mode of ['client', 'server']) {
    assert.throws(
      () => run(process.execPath, [cliPath, mode, '--transport', 'websocket', '--artifact', rejected], consumerDir),
      (error) => error?.status === 1 && error?.stderr === 'invalid_artifact\n',
      `${mode} CLI must reject v2 artifacts without fallback`,
    );
  }

  const certificate = path.join(consumerDir, 'cli-cert.pem');
  const privateKey = path.join(consumerDir, 'cli-key.pem');
  run('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-sha256', '-nodes', '-days', '2', '-subj', '/CN=localhost',
    '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature',
    '-addext', 'extendedKeyUsage=serverAuth',
    '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', privateKey, '-out', certificate,
  ], consumerDir);

  const origin = 'https://cli.example';
  const port = await reservePort();
  const artifact = JSON.parse(artifactFixture);
  artifact.path.candidates = [{
    ...artifact.path.candidates.find((candidate) => candidate.carrier === 'websocket'),
    url: `wss://localhost:${port}/flowersec/v3/direct`,
  }];
  const artifactPath = path.join(consumerDir, 'cli-artifact.json');
  const spendMarker = path.join(consumerDir, 'cli-spend.marker');
  fs.writeFileSync(artifactPath, JSON.stringify(artifact));

  const serverArguments = [
    cliPath, 'server', '--transport', 'websocket', '--artifact', artifactPath,
    '--certificate', certificate, '--private-key', privateKey,
    '--host', '127.0.0.1', '--port', String(port), '--origin', origin,
    '--max-inbound-streams', String(artifact.session.max_inbound_streams),
  ];
  const clientArguments = [
    cliPath, 'client', '--transport', 'websocket', '--artifact', artifactPath,
    '--ca', certificate, '--origin', origin, '--spend-marker', spendMarker,
  ];

  const firstServer = await startCLIServer(serverArguments, port);
  const firstClient = await runCLI(clientArguments);
  assert.deepEqual(firstClient, { code: 0, stdout: 'GREEN\n', stderr: '' });
  assert.equal(fs.existsSync(spendMarker), true, 'CLI must commit the artifact spend exactly once');
  assert.equal(await waitForExit(firstServer.child), 0, firstServer.stderr.join(''));

  const secondServer = await startCLIServer(serverArguments, port);
  const secondClient = await runCLI(clientArguments);
  assert.equal(secondClient.code, 1, 'a spent artifact must not be reusable');
  assert.equal(secondClient.stderr, 'connection_failed\n');
  assert.equal(await waitForExit(secondServer.child), 1, secondServer.stderr.join(''));

  const signalServer = await startCLIServer(serverArguments, port);
  signalServer.child.kill('SIGTERM');
  assert.equal(await waitForExit(signalServer.child), 0, signalServer.stderr.join(''));
}

async function reservePort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.equal(typeof address, 'object');
  const port = address.port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function startCLIServer(arguments_, expectedPort) {
  const child = spawn(process.execPath, arguments_, { cwd: consumerDir, stdio: ['ignore', 'pipe', 'pipe'] });
  const stderr = [];
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => stderr.push(chunk));
  const line = await firstLine(child.stdout, child);
  const address = JSON.parse(line);
  assert.equal(address.port, expectedPort);
  return { child, stderr };
}

async function runCLI(arguments_) {
  const child = spawn(process.execPath, arguments_, { cwd: consumerDir, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  return { code: await waitForExit(child), stdout, stderr };
}

async function firstLine(stream, child) {
  stream.setEncoding('utf8');
  let buffered = '';
  for await (const chunk of stream) {
    buffered += chunk;
    const newline = buffered.indexOf('\n');
    if (newline >= 0) return buffered.slice(0, newline);
  }
  throw new Error(`CLI server exited before reporting its address (status ${child.exitCode})`);
}

async function waitForExit(child) {
  if (child.exitCode !== null) return child.exitCode;
  return await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('CLI process did not exit within 10 seconds'));
    }, 10_000);
    child.once('exit', (code) => {
      clearTimeout(timeout);
      resolve(code ?? 1);
    });
    child.once('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

try {
  verifyPackageJSONExports();
  const tarballName = packTarball();
  const tarballPath = path.join(packDir, tarballName);
  assert.equal(fs.existsSync(tarballPath), true, 'packed tarball must exist');
  installTarball(tarballPath);
  verifyBrowserDependencyGraph();
  verifyInstalledDeclarationClosure();
  verifyInstalledPackage();
  await verifyPackedBin();
  verifyArtifactOnlyConnectTypes();
  verifyCurrentTypes();
} finally {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
}
