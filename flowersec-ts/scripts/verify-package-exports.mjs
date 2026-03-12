import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'flowersec-package-verify-'));
const packDir = path.join(tmpRoot, 'pack');
const consumerDir = path.join(tmpRoot, 'consumer');

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
    return run('npm', ['pack', '--silent', '--pack-destination', packDir], pkgRoot).trim();
  } catch {
    const name = run('npm', ['pack', '--silent'], pkgRoot).trim();
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

function verifyInstalledPackage() {
  const script = `
    import assert from 'node:assert/strict';

    const core = await import('@floegence/flowersec-core');
    assert.equal(typeof core.connect, 'function');
    assert.equal(typeof core.connectTunnel, 'function');
    assert.equal(typeof core.connectDirect, 'function');
    assert.equal(typeof core.FlowersecError, 'function');
    assert.equal('RpcCallError' in core, false);

    const node = await import('@floegence/flowersec-core/node');
    assert.equal(typeof node.connectNode, 'function');
    assert.equal(typeof node.connectTunnelNode, 'function');
    assert.equal(typeof node.connectDirectNode, 'function');
    assert.equal(typeof node.createNodeWsFactory, 'function');

    const browser = await import('@floegence/flowersec-core/browser');
    assert.equal(typeof browser.connectBrowser, 'function');
    assert.equal(typeof browser.connectTunnelBrowser, 'function');
    assert.equal(typeof browser.connectDirectBrowser, 'function');

    const rpc = await import('@floegence/flowersec-core/rpc');
    assert.equal(typeof rpc.RpcClient, 'function');
    assert.equal(typeof rpc.RpcServer, 'function');
    assert.equal(typeof rpc.RpcCallError, 'function');
    assert.equal(typeof rpc.callTyped, 'function');
    assert.equal('readJsonFrame' in rpc, false);
    assert.equal('writeJsonFrame' in rpc, false);

    const framing = await import('@floegence/flowersec-core/framing');
    assert.equal(typeof framing.readJsonFrame, 'function');
    assert.equal(typeof framing.writeJsonFrame, 'function');
    assert.equal(typeof framing.JsonFramingError, 'function');
    assert.equal(typeof framing.DEFAULT_MAX_JSON_FRAME_BYTES, 'number');

    const streamio = await import('@floegence/flowersec-core/streamio');
    assert.equal(typeof streamio.readMaybe, 'function');
    assert.equal(typeof streamio.createByteReader, 'function');
    assert.equal(typeof streamio.readExactly, 'function');
    assert.equal(typeof streamio.readNBytes, 'function');

    const proxy = await import('@floegence/flowersec-core/proxy');
    assert.equal(typeof proxy.createProxyRuntime, 'function');
    assert.equal(typeof proxy.createProxyServiceWorkerScript, 'function');
    assert.equal(typeof proxy.createProxyIntegrationServiceWorkerScript, 'function');
    assert.equal(typeof proxy.registerProxyIntegration, 'function');
    assert.equal(typeof proxy.registerServiceWorkerAndEnsureControl, 'function');
    assert.equal(typeof proxy.connectTunnelProxyBrowser, 'function');
    assert.equal(typeof proxy.createServiceWorkerControllerGuard, 'function');
    assert.equal(typeof proxy.registerProxyControllerWindow, 'function');
    assert.equal(typeof proxy.registerProxyAppWindow, 'function');
    assert.equal(typeof proxy.resolveProxyProfile, 'function');
    assert.equal(typeof proxy.installWebSocketPatch, 'function');
    assert.equal(typeof proxy.disableUpstreamServiceWorkerRegister, 'function');

    const reconnect = await import('@floegence/flowersec-core/reconnect');
    assert.equal(typeof reconnect.createReconnectManager, 'function');
    const mgr = reconnect.createReconnectManager();
    assert.equal(typeof mgr.connectIfNeeded, 'function');

    const yamux = await import('@floegence/flowersec-core/yamux');
    assert.equal(typeof yamux.YamuxSession, 'function');
    assert.equal(typeof yamux.ByteReader, 'function');
    assert.equal(typeof yamux.StreamEOFError, 'function');
    assert.equal(typeof yamux.isStreamEOFError, 'function');

    const e2ee = await import('@floegence/flowersec-core/e2ee');
    assert.equal(typeof e2ee.clientHandshake, 'function');
    assert.equal(typeof e2ee.SecureChannel, 'function');

    const ws = await import('@floegence/flowersec-core/ws');
    assert.equal(typeof ws.WebSocketBinaryTransport, 'function');

    const obs = await import('@floegence/flowersec-core/observability');
    assert.equal(typeof obs.normalizeObserver, 'function');
    assert.equal(typeof obs.nowSeconds, 'function');

    const sh = await import('@floegence/flowersec-core/streamhello');
    assert.equal(typeof sh.readStreamHello, 'function');
    assert.equal(typeof sh.writeStreamHello, 'function');

    const rpcGen = await import('@floegence/flowersec-core/gen/flowersec/rpc/v1.gen');
    assert.equal(typeof rpcGen.assertRpcError, 'function');
  `;

  run(process.execPath, ['--input-type=module', '-'], consumerDir, script);
}

try {
  const tarballName = packTarball();
  const tarballPath = path.join(packDir, tarballName);
  assert.equal(fs.existsSync(tarballPath), true, 'packed tarball must exist');
  installTarball(tarballPath);
  verifyInstalledPackage();
} finally {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
}
