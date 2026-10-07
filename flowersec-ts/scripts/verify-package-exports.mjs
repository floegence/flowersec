import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(pkgRoot, '..');
const artifactRoot = process.env.FLOWERSEC_TASK_ARTIFACT_DIR ?? path.join(path.dirname(repoRoot), 'flowersec-package-check-artifacts');
fs.mkdirSync(artifactRoot, { recursive: true });
const tmpRoot = fs.mkdtempSync(path.join(artifactRoot, 'package-consumer-'));
const commandLogs = [];
let completed = false;
const packDir = path.join(tmpRoot, 'pack');
const consumerDir = path.join(tmpRoot, 'consumer');
const manifest = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'stability', 'api_contract_manifest.json'), 'utf8')
);
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
  'v2', 'parseArtifact', 'createArtifactLease', 'Artifact', 'ArtifactLease',
  'ConnectError', 'ByteStream',
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
  try { return execFileSync(cmd, args, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
    ...(input == null ? {} : { input }),
  }); } catch (error) {
    commandLogs.push(`${cmd} ${args.join(' ')}\n${String(error.stdout ?? '').slice(0, 1048576)}\n${String(error.stderr ?? '').slice(0, 1048576)}`);
    throw error;
  }
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
  // The Node entrypoint requires the same explicitly pinned ambient types as
  // an ordinary Node consumer; compiler location must not supply them by chance.
  const packageJSON = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
  const nodeTypesVersion = packageJSON.dependencies['@types/node'];
  assert.match(nodeTypesVersion, /^\d+\.\d+\.\d+$/u);
  run('npm', ['install', '--ignore-scripts', '--no-package-lock', tarballPath, `@types/node@${nodeTypesVersion}`], consumerDir);
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
  assert.equal(bareSpecifiers.some(specifier => specifier.startsWith('node:') || ['ws', 'fs', 'net', 'tls'].includes(specifier)), false, 'browser dependency graph must not load Node transports');
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

function verifyInstalledTypeExports() {
  const installedRoot = path.join(consumerDir, 'node_modules', '@floegence', 'flowersec-core');
  const installedPackage = JSON.parse(fs.readFileSync(path.join(installedRoot, 'package.json'), 'utf8'));
  const entries = manifest.ts.subpaths.map((subpath) => ({
    subpath,
    file: path.join(installedRoot, installedPackage.exports[subpath.package_json_export].types),
  }));
  const program = ts.createProgram(entries.map((entry) => entry.file), {
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    target: ts.ScriptTarget.ES2022,
    skipLibCheck: true,
  });
  const checker = program.getTypeChecker();
  for (const { subpath, file } of entries) {
    const source = program.getSourceFile(file);
    assert.notEqual(source, undefined, `missing installed declaration for ${subpath.specifier}`);
    const module = checker.getSymbolAtLocation(source);
    assert.notEqual(module, undefined, `missing declaration module for ${subpath.specifier}`);
    const actual = checker.getExportsOfModule(module).filter((symbol) => {
      const target = symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
      return Boolean(target.flags & ts.SymbolFlags.Type);
    }).map((symbol) => symbol.getName()).sort();
    assert.deepEqual(actual, [...subpath.type_exports].sort(), `${subpath.specifier} type export set drifted from the API contract manifest`);
  }
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
    const node = await import('@floegence/flowersec-core/node');
    const proxy = await import('@floegence/flowersec-core/proxy');
    for (const name of ['TransportEnvironment', 'ResourceRoot', 'ResourceVector', 'Session', 'connect', 'createConnectionController', 'createStreamMetadata']) {
      assert.equal(root[name], browser[name], 'browser must share the current original owner: ' + name);
      assert.equal(root[name], node[name], 'Node must share the current original owner: ' + name);
    }
    for (const entry of [root, browser, node, proxy]) {
      for (const name of ['PreauthorizedPoolSource', 'TopUpHandle', 'createSessionPoolControl']) assert.equal(entry[name], root[name], 'pool operation owner differs across entrypoints: ' + name);
      for (const name of ['createOriginalPoolSource', 'registerPoolJournalStore', 'proxyRequestAssociation', 'serviceWorkerPublicationOwner']) assert.equal(Object.prototype.hasOwnProperty.call(entry, name), false, 'private operation authority escaped: ' + name);
    }
    for (const name of ['status', 'cleanupStatus', 'waitCleanup']) assert.equal(typeof root.TopUpHandle.prototype[name], 'function');
    for (const name of ['id', 'operationID', 'operation_id']) assert.equal(name in root.TopUpHandle.prototype, false, 'wire operation identity escaped through TopUpHandle: ' + name);
    assert.equal(typeof proxy.createProxySurface, 'function');
    for (const entry of [root, browser, node]) assert.equal(Object.prototype.hasOwnProperty.call(entry, 'createProxySurface'), false, 'surface composition belongs to the proxy entrypoint');
    for (const name of ['configureBrowserWSS', 'configureBrowserWebTransport', 'createIndexedDBPoolBacking', 'createBrowserLiveHTTPS']) assert.equal(typeof browser[name], 'function');
    for (const name of ['createAcceptor', 'createGrantIssuer', 'createTunnelRuntime', 'createRegisteredPoolTunnelServer', 'createRegisteredLiveTunnelServer', 'createRegisteredLiveTunnelControlAuthority', 'createRegisteredLiveTunnelClientAuthorization']) assert.equal(typeof node[name], 'function');
    const limit = new root.ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 1000n, 1000n, 1000n, 1000n, 1000n, 1000n]);
    const budget = new root.ResourceRoot({ profileRevision: '1'.repeat(64), limit, accounts: 128, reservations: 256, references: 512,
      rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
    const now = BigInt(Date.now()), start = performance.now();
    const environment = root.createTransportEnvironment({ root: budget, limit, tenantLimit: limit, tenantID: '1'.repeat(32), environmentID: '2'.repeat(32),
      runtimeBytes: 1024n, namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, dependencies: 8, acquireMS: 10000n, cleanupMS: 10000,
      random: destination => crypto.getRandomValues(destination), clock: { profile: { rate: new root.ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 60000n, maxRoundTripMS: 100n },
        tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - start)), incarnation: '3'.repeat(32) }), initial: () => ({ lowerMS: now, upperMS: now }) } });
    try { await assert.rejects(root.connect(environment, {})); }
    finally { await environment.close(); assert.equal((await environment.waitCleanup()).status, 'complete'); assert.equal(budget.snapshot().reservations, 0); budget.close(); }
  `;

  run(process.execPath, ['--input-type=module', '-'], consumerDir, script);
}

function writeConsumerTypeConfiguration() {
  fs.writeFileSync(path.join(consumerDir, 'tsconfig.json'), JSON.stringify({ compilerOptions: {
    module: 'NodeNext', moduleResolution: 'NodeNext', noEmit: true, strict: true, target: 'ES2022', types: ['node'],
  }, include: ['*.ts'] }, null, 2));
  fs.writeFileSync(path.join(consumerDir, 'removed-api.ts'), `
// @ts-expect-error artifacts are opaque provider material, never public lease owners.
import { parseArtifact, createArtifactLease, connectDirect, connectTunnel } from '@floegence/flowersec-core';
void [parseArtifact, createArtifactLease, connectDirect, connectTunnel];
`);
}

function verifyCurrentTypes() {
  writeConsumerTypeConfiguration();
  writeConnectionTypeConsumers();
  fs.writeFileSync(path.join(consumerDir, 'current-api.ts'), `
import { connect, connectMaterial, createConnectionController, createStreamMetadata } from '@floegence/flowersec-core';
import type { TransportEnvironment, Session, Stream, ConnectionMaterial, ConnectionMaterialSource, ConnectionRequirements } from '@floegence/flowersec-core';
import { createAcceptor, createRegisteredPoolTunnelServer, createRegisteredLiveTunnelServer, createRegisteredLiveTunnelControlAuthority, createRegisteredLiveTunnelClientAuthorization } from '@floegence/flowersec-core/node';
import type { AcceptorOptions, RegisteredPoolTunnelServerOptions, RegisteredLiveTunnelServerOptions, RegisteredLiveTunnelControlAuthorityOptions, RegisteredLiveTunnelClientOptions } from '@floegence/flowersec-core/node';
declare const environment: TransportEnvironment, source: ConnectionMaterialSource, material: ConnectionMaterial, requirements: ConnectionRequirements, stream: Stream;
declare const acceptor: AcceptorOptions, pool: RegisteredPoolTunnelServerOptions, live: RegisteredLiveTunnelServerOptions, authority: RegisteredLiveTunnelControlAuthorityOptions, authorization: RegisteredLiveTunnelClientOptions;
const connected: Promise<Session> = connect(environment, source, requirements);
const prepared: Promise<Session> = connectMaterial(environment, material);
const controller = createConnectionController(environment, { source, requirements });
void createAcceptor(acceptor); void createRegisteredPoolTunnelServer(pool); void createRegisteredLiveTunnelServer(live);
void createRegisteredLiveTunnelControlAuthority(authority); void createRegisteredLiveTunnelClientAuthorization(environment, authorization);
void createStreamMetadata({ purpose: 'package-check' }); void stream.closeWrite(); void connected; void prepared; void controller;
// @ts-expect-error connection requires an original Environment and configured source.
void connect({ artifact_json: '{}' });
`);
  fs.writeFileSync(path.join(consumerDir, 'pool-surface-api.ts'), `
import { createSessionPoolControl } from '@floegence/flowersec-core';
import type { PreauthorizedPoolSource, TopUpHandle, PoolSourceConfiguration, TopUpOptions, TopUpState, TopUpResult, TopUpControlTransport, TopUpExchangeResult, PoolControlReplyDecoder, CleanupStatus, OperationOptions, ServiceClient, MethodDefinition } from '@floegence/flowersec-core';
import { createProxySurface } from '@floegence/flowersec-core/proxy';
import type { ProxySurface, ProxySurfaceOptions, ProxySurfaceMode, ProxySessionBinding, ProxySurfaceRequestPolicy, ProxyPublicationOwner, ProxyClearResult } from '@floegence/flowersec-core/proxy';
import type { ProxyCredentialPolicy, ProxyCookieScope, ProxyCredentialAuthentication, NodeWSSClient } from '@floegence/flowersec-core/node';
import type { BrowserWSSClient, BrowserWebTransportClient } from '@floegence/flowersec-core/browser';
declare const source: PreauthorizedPoolSource, handle: TopUpHandle, configuration: PoolSourceConfiguration, options: TopUpOptions, wait: OperationOptions;
declare const topUpMethod: MethodDefinition<Uint8Array, Uint8Array, 'unary', 'transient'>, ackMethod: MethodDefinition<Uint8Array, Uint8Array, 'unary', 'transient'>;
declare const client: ServiceClient<{ topUp: typeof topUpMethod; ack: typeof ackMethod }>, decoder: PoolControlReplyDecoder;
const control: TopUpControlTransport = createSessionPoolControl(client, topUpMethod, ackMethod, decoder, 1000n);
const observed: Promise<TopUpResult> = source.topUp(options, wait), status: Promise<TopUpResult> = handle.status(wait);
const originalCleanup: Promise<CleanupStatus> = handle.waitCleanup(wait), sourceCleanup: Promise<CleanupStatus> = source.waitCleanup(wait);
const cleanup: CleanupStatus = handle.cleanupStatus();
// @ts-expect-error Wire operation IDs stay behind the opaque observation owner.
void handle.id;
declare const nodeClient: NodeWSSClient, browserClient: BrowserWSSClient, webTransportClient: BrowserWebTransportClient;
declare const credentialPolicy: import('@floegence/flowersec-core').CredentialPolicy;
for (const configured of [nodeClient, browserClient, webTransportClient]) {
  const registered: Promise<PreauthorizedPoolSource> = configured.registerDurablePoolSource(credentialPolicy, configuration);
  void registered;
}
const state: TopUpState = 'installed';
declare const exchange: TopUpExchangeResult, surface: ProxySurface, surfaceOptions: ProxySurfaceOptions, mode: ProxySurfaceMode, binding: ProxySessionBinding;
declare const requestPolicy: ProxySurfaceRequestPolicy, publication: ProxyPublicationOwner, credentials: ProxyCredentialPolicy, scope: ProxyCookieScope, authentication: ProxyCredentialAuthentication;
const created: Promise<ProxySurface> = createProxySurface(surfaceOptions);
const cleared: Promise<ProxyClearResult> = surface.clearUpstreamCredentials({ reuseAfterClear: true, signal: wait.signal });
void [configuration, control, observed, status, originalCleanup, sourceCleanup, cleanup, state, exchange, created, cleared, mode, binding, requestPolicy, publication, credentials, scope, authentication];
`);
  run(process.execPath, [path.join(pkgRoot, 'node_modules', 'typescript', 'bin', 'tsc6'), '-p', 'tsconfig.json'], consumerDir);
}

function writeConnectionTypeConsumers() {
  const clients = [
    { entry: '', runtime: '/node', configure: 'configureNodeWSS', config: 'NodeWSSClientConfig' },
    { entry: '/node', runtime: '/node', configure: 'configureNodeWSS', config: 'NodeWSSClientConfig' },
    { entry: '/browser', runtime: '/browser', configure: 'configureBrowserWSS', config: 'BrowserWSSClientConfig' },
    { entry: '/browser', runtime: '/browser', configure: 'configureBrowserWebTransport', config: 'BrowserWebTransportClientConfig' },
  ];
  for (const [index, client] of clients.entries()) {
    fs.writeFileSync(path.join(consumerDir, `connection-${index}.ts`), `
import { connect, createConnectionController } from '@floegence/flowersec-core${client.entry}';
import type {
  ConnectionMaterialSource, ConnectionRequirements, ConnectionController,
  NamespaceOptions, CredentialPolicy, CredentialBuffers,
  CredentialLengths, CredentialProvider, Session, TransportEnvironment,
} from '@floegence/flowersec-core${client.entry}';
import { ${client.configure} } from '@floegence/flowersec-core${client.runtime}';
import type { ${client.config} } from '@floegence/flowersec-core${client.runtime}';

declare function fillCredentials(
  signal: AbortSignal, requirements: ConnectionRequirements, buffers: CredentialBuffers,
): Promise<CredentialLengths>;

export async function configure(
  environment: TransportEnvironment, config: ${client.config},
  namespace: NamespaceOptions, policy: CredentialPolicy, sourceKind: 'live' | 'pool',
) {
  const client = await ${client.configure}(environment, config);
  client.namespace(namespace);
  const provider: CredentialProvider = ({ signal, requirements }, buffers) =>
    fillCredentials(signal, requirements, buffers);
  const source: ConnectionMaterialSource = sourceKind === 'live'
    ? client.registerLiveSource(policy, provider)
    : client.registerPoolSource(policy, provider);
  const controller: ConnectionController = createConnectionController(environment, { source });
  const open = (): Promise<Session> => connect(environment, source);
  return { source, controller, open };
}
`);
  }
}

async function verifyPackedBin() {
  const installedRoot = path.join(consumerDir, 'node_modules', '@floegence', 'flowersec-core');
  const cliPath = path.join(installedRoot, 'dist', 'cli.js');
  assert.match(fs.readFileSync(cliPath, 'utf8'), /^#!\/usr\/bin\/env node/u);
  assert.equal((fs.statSync(cliPath).mode & 0o111) !== 0, true, 'CLI must be executable');
  for (const mode of ['client', 'server']) {
    assert.deepEqual(await runCLI([cliPath, mode]), { code: 1, stdout: '', stderr: 'missing_option:config\n' });
    assert.deepEqual(await runCLI([cliPath, mode, '--artifact', 'untrusted.json']), { code: 1, stdout: '', stderr: 'missing_option:config\n' });
    const config = path.join(consumerDir, `trusted-${mode}.mjs`);
    fs.writeFileSync(config, `import assert from 'node:assert/strict';
export default { ${mode}(values, operation) {
  assert.equal(Object.isFrozen(values), true);
  assert.equal(values.message, 'consumer-value');
  assert.equal(operation.signal instanceof AbortSignal, true);
  throw new Error('installed_configuration_called');
} };
`);
    assert.deepEqual(await runCLI([cliPath, mode, '--config', config, '--message', 'consumer-value']), { code: 1, stdout: '', stderr: 'installed_configuration_called\n' });
    assert.deepEqual(await runCLI([cliPath, mode, '--config', config, '--config', config]), { code: 1, stdout: '', stderr: 'duplicate_option\n' });
  }
}

async function runCLI(arguments_) {
  const child = spawn(process.execPath, arguments_, { cwd: consumerDir, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const result = { code: await waitForExit(child), stdout, stderr };
  commandLogs.push(`CLI ${arguments_.slice(1).join(' ')}\n${stdout.slice(0, 1048576)}\n${stderr.slice(0, 1048576)}`);
  return result;
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
      clearTimeout(timeout); reject(error);
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
  verifyInstalledTypeExports();
  verifyInstalledPackage();
  await verifyPackedBin();
  verifyCurrentTypes();
  completed = true;
} finally {
  if (!completed && commandLogs.length > 0) {
    const log = Buffer.from(commandLogs.join('\n'));
    const digest = createHash('sha256').update(log).digest('hex');
    const retained = path.join(artifactRoot, `package-failure-${digest}.log`);
    fs.writeFileSync(retained, log); fs.writeFileSync(`${retained}.sha256`, `${digest}  ${path.basename(retained)}\n`);
    assert.equal(createHash('sha256').update(fs.readFileSync(retained)).digest('hex'), digest);
    log.fill(0);
  }
  fs.rmSync(tmpRoot, { recursive: true, force: true });
}
