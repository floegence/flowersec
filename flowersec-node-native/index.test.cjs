"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const loaderSource = fs.readFileSync(path.join(__dirname, "index.js"), "utf8");

const supportedPlatforms = [
  ["darwin", "arm64", undefined, "@floegence/flowersec-node-native-darwin-arm64"],
  ["darwin", "x64", undefined, "@floegence/flowersec-node-native-darwin-x64"],
  ["linux", "arm64", "2.35", "@floegence/flowersec-node-native-linux-arm64-gnu"],
  ["linux", "x64", "2.35", "@floegence/flowersec-node-native-linux-x64-gnu"],
];

for (const [platform, arch, glibcVersion, expectedPackage] of supportedPlatforms) {
  test(`loads ${expectedPackage} for ${platform}-${arch}`, () => {
    const addon = nativeAddon();
    const loaded = executeLoader({ platform, arch, glibcVersion, resolve: (specifier) => {
      assert.equal(specifier, expectedPackage);
      return addon;
    } });

    assert.equal(loaded.error, undefined);
    assert.equal(loaded.exports.contractVersion(), 4);
    assert.equal(typeof loaded.exports.connectRawQuic, "function");
    assert.equal(typeof loaded.exports.bindRawQuic, "function");
    assert.equal(typeof loaded.exports.createPreparationBudget, "function");
    assert.deepEqual(loaded.requests, [expectedPackage]);
  });
}

test("rejects Linux musl without attempting to load a glibc package", () => {
  const loaded = executeLoader({ platform: "linux", arch: "x64" });

  assert.equal(loaded.requests.length, 0);
  assertUnavailable(loaded.error);
});

test("rejects an unknown platform and architecture without resolving a package", () => {
  const loaded = executeLoader({ platform: "win32", arch: "x64", glibcVersion: "2.35" });

  assert.equal(loaded.requests.length, 0);
  assertUnavailable(loaded.error);
});

test("maps a missing optional package to the public unavailable error", () => {
  const loaded = executeLoader({
    platform: "linux",
    arch: "x64",
    glibcVersion: "2.35",
    resolve: () => {
      const error = new Error("Cannot find module");
      error.code = "MODULE_NOT_FOUND";
      throw error;
    },
  });

  assert.deepEqual(loaded.requests, ["@floegence/flowersec-node-native-linux-x64-gnu"]);
  assertUnavailable(loaded.error);
});

test("maps native binary initialization failure to the public unavailable error", () => {
  const loaded = executeLoader({
    platform: "darwin",
    arch: "arm64",
    resolve: () => { throw new Error("dlopen failed: invalid binary"); },
  });

  assert.deepEqual(loaded.requests, ["@floegence/flowersec-node-native-darwin-arm64"]);
  assertUnavailable(loaded.error);
});

test("preserves the original preparation factory, opaque handle and actual native continuation", async () => {
  const input = { preauthInputBytes: 262144, addressAttempts: 2, workUnits: 256 };
  const handle = Object.freeze({});
  const usage = { preauthInputBytes: 41, addressAttempts: 1, workUnits: 3 };
  let factories = 0, configured, closed = 0, canceled = 0, completed = 0;
  const budget = { configure: limits => { configured = limits; }, beginCandidate: () => handle, usage: () => usage, close: () => { closed++; } };
  const delivered = deferred(), terminated = deferred();
  const original = nativeSession("raw_quic", () => { completed++; }, terminated.promise);
  const addon = nativeAddon({ createPreparationBudget: () => { factories++; return budget; }, connectRawQuic: options => {
    assert.equal(options.preparationBudget, handle);
    return { cancel: () => { canceled++; }, result: () => delivered.promise };
  } });
  const loaded = executeLoader({ platform: "darwin", arch: "arm64", resolve: () => addon });
  const owner = loaded.exports.createPreparationBudget();
  assert.equal(owner, budget); owner.configure(input); assert.equal(configured, input);
  assert.equal(owner.beginCandidate(input), handle); assert.equal(owner.usage(), usage);
  const connecting = loaded.exports.connectRawQuic({ preparationBudget: handle });
  connecting.cancel(); assert.equal(canceled, 1); assert.equal(closed, 0);
  const result = connecting.result(); assert.equal(connecting.result(), result);
  delivered.resolve(original);
  const session = await result;
  session.completePreparation(); session.completePreparation();
  assert.equal(completed, 1); assert.equal(factories, 1); assert.equal(owner.usage(), usage); assert.equal(closed, 0);
  let settled = false;
  const ending = session.waitTermination().then(() => { settled = true; });
  await Promise.resolve(); assert.equal(settled, false);
  terminated.resolve(); await ending; assert.equal(settled, true); assert.equal(closed, 0);
  owner.close(); assert.equal(closed, 1); assert.equal(factories, 1);
});

for (const kind of ["raw_quic", "webtransport"]) {
  test(`passes shared ${kind} capacity and completes each original accepted session once`, async () => {
    const capacity = { preauthInputBytes: 1048576, addressAttempts: 1, workUnits: 4096 };
    const completions = [0, 0];
    const originals = completions.map((_, index) => nativeSession(kind, () => { completions[index]++; }));
    let observed;
    const bind = options => {
      observed = options;
      let next = 0;
      return Promise.resolve({ address: () => ({ host: "127.0.0.1", port: 20000 }),
        accept: () => ({ result: () => Promise.resolve(originals[next++]), cancel: () => {} }),
        waitTermination: () => Promise.resolve(), close: () => Promise.resolve(), abort: () => {} });
    };
    const addon = nativeAddon({ bindRawQuic: bind, bindWebTransport: bind });
    const loaded = executeLoader({ platform: "darwin", arch: "arm64", resolve: () => addon });
    const options = { host: "127.0.0.1", port: 20000, path: "direct", certificateChainDer: [new Uint8Array([1])], privateKeyDer: new Uint8Array([2]),
      inboundBidirectionalStreamCapacity: 3, readBufferBytes: 16384, datagramQueueBytes: 65536, handshakeTimeoutMs: 10000,
      pendingConnections: 2, incomingPreparationCapacity: capacity,
      ...(kind === "raw_quic" ? {} : { serverName: "localhost", connectPath: "/flowersec/webtransport/v4/direct", tuples: ["native_h3"],
        allowedOrigins: [], allowAbsentOrigin: true, headerBytes: 16384, controlBytes: 65536 }) };
    const listener = await loaded.exports[kind === "raw_quic" ? "bindRawQuic" : "bindWebTransport"](options);
    assert.equal(observed, options); assert.equal(observed.incomingPreparationCapacity, capacity);
    assert.equal(observed.preparationBudget, undefined); assert.equal(observed.pendingConnections, 2);
    const first = await listener.accept().result(), second = await listener.accept().result();
    assert.equal(first.kind, kind); assert.equal(second.kind, kind);
    first.completePreparation(); first.completePreparation(); assert.deepEqual(completions, [1, 0]);
    second.completePreparation(); second.completePreparation(); assert.deepEqual(completions, [1, 1]);
  });
}

test("does not synthesize preparation capabilities absent from the native provider", async () => {
  const original = nativeSession("raw_quic", undefined);
  const addon = nativeAddon({ createPreparationBudget: undefined,
    connectRawQuic: () => ({ result: () => Promise.resolve(original), cancel: () => {} }) });
  const loaded = executeLoader({ platform: "darwin", arch: "arm64", resolve: () => addon });
  assert.equal(loaded.error, undefined); assert.equal(loaded.exports.createPreparationBudget, undefined);
  const session = await loaded.exports.connectRawQuic({}).result();
  assert.equal(session.completePreparation, undefined);
});

test("does not cache failed preparation completion as success", async () => {
  const failure = new Error("preparation_budget_exhausted");
  let attempts = 0;
  const original = nativeSession("raw_quic", () => { attempts++; throw failure; });
  const addon = nativeAddon({ connectRawQuic: () => ({ result: () => Promise.resolve(original), cancel: () => {} }) });
  const loaded = executeLoader({ platform: "darwin", arch: "arm64", resolve: () => addon });
  const session = await loaded.exports.connectRawQuic({}).result();
  assert.throws(() => session.completePreparation(), error => error === failure);
  assert.throws(() => session.completePreparation(), error => error === failure);
  assert.equal(attempts, 2);
});

function deferred() {
  let resolve;
  const promise = new Promise(yes => { resolve = yes; });
  return { promise, resolve };
}
function nativeAddon(overrides = {}) {
  return Object.freeze({ contractVersion: () => 4,
    createPreparationBudget: () => { throw new Error("unused preparation factory"); },
    connectRawQuic: () => { throw new Error("unused raw connect"); }, bindRawQuic: () => { throw new Error("unused raw bind"); },
    connectWebTransport: () => { throw new Error("unused WebTransport connect"); }, bindWebTransport: () => { throw new Error("unused WebTransport bind"); },
    ...overrides });
}
function nativeSession(kind, completePreparation, termination = Promise.resolve()) {
  return { kind, path: "direct", wireVersion: 4, inboundBidirectionalStreamCapacity: 3,
    completePreparation, waitTermination: () => termination,
    request: () => ({ scheme: "https", authority: "localhost:20000", path: "/flowersec/webtransport/v4/direct", tuple: "native_h3",
      protocol: "webtransport-h3", sessionFlowControl: false, streamPrefixes: "rfc_webtransport", datagramContext: "rfc_h3_quarter_stream_id" }) };
}

function executeLoader({ platform, arch, glibcVersion, resolve = () => undefined }) {
  const requests = [];
  const module = { exports: {} };
  let error;
  try {
    vm.runInNewContext(loaderSource, {
      Error,
      Object,
      module,
      process: {
        platform,
        arch,
        report: glibcVersion === undefined
          ? { getReport: () => ({ header: {} }) }
          : { getReport: () => ({ header: { glibcVersionRuntime: glibcVersion } }) },
      },
      require: (specifier) => {
        requests.push(specifier);
        return resolve(specifier);
      },
    }, { filename: "flowersec-node-native/index.js" });
  } catch (cause) {
    error = cause;
  }
  return { exports: module.exports, requests, error };
}

function assertUnavailable(error) {
  assert.ok(error instanceof Error);
  assert.equal(error.message, "Flowersec native transport is unavailable on this platform");
  assert.equal(error.code, "native_transport_unavailable");
}
