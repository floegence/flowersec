"use strict";

const platformPackages = Object.freeze({
  "darwin-arm64": "@floegence/flowersec-node-native-darwin-arm64",
  "darwin-x64": "@floegence/flowersec-node-native-darwin-x64",
  "linux-arm64": "@floegence/flowersec-node-native-linux-arm64-gnu",
  "linux-x64": "@floegence/flowersec-node-native-linux-x64-gnu",
});

const platformKey = `${process.platform}-${process.arch}`;
const platformPackage = platformPackages[platformKey];
if (platformPackage === undefined || (process.platform === "linux" && !isGlibc())) {
  throw unavailable();
}

try {
  module.exports = currentBinding(require(platformPackage));
} catch {
  throw unavailable();
}

function isGlibc() {
  const report = process.report?.getReport?.();
  return typeof report?.header?.glibcVersionRuntime === "string";
}

function unavailable() {
  const error = new Error("Flowersec native transport is unavailable on this platform");
  error.code = "native_transport_unavailable";
  return error;
}

// The facade caches only observations of the original native operation. It
// never races a cancellation against completion or manufactures early release.
function directionError(error) {
  if (error instanceof Error && (error.message === "normal_drained" || error.message === "direction_reset")) {
    Object.defineProperties(error, { source: { value: "stream" }, reason: { value: error.message } });
  }
  return error;
}
function actualPromise(run) {
  try { return Promise.resolve(run()).catch(error => { throw directionError(error); }); }
  catch (error) { return Promise.reject(directionError(error)); }
}
function operation(native, project) {
  let result;
  return Object.freeze({
    cancel: () => native.cancel(),
    result: () => result ??= actualPromise(() => native.result()).then(project),
  });
}
function submission(native) {
  if (native == null) return undefined;
  // Capture immediately, so a discarded JS observer cannot strand an admitted
  // native owner or leave its once-only completion accessor unobserved.
  const completion = actualPromise(() => native.completion());
  void completion.catch(() => {});
  return Object.freeze({ completion: () => completion });
}
function stream(native) {
  const termination = actualPromise(() => native.waitTermination());
  void termination.catch(() => {});
  const writeFailure = actualPromise(() => native.waitWriteFailure());
  void writeFailure.catch(() => {});
  let observer;
  let failure;
  void writeFailure.then(reason => {
    failure = reason;
    if (reason != null && observer !== undefined) observer.callback(reason);
  }).catch(() => {});
  return Object.freeze({
    read: maximum => operation(native.read(maximum), bytes => bytes == null ? null : bytes),
    submit: bytes => submission(native.submit(bytes)),
    closeWrite: () => actualPromise(() => native.closeWrite()),
    stopSending: reason => actualPromise(() => native.stopSending(reason)),
    resetWrite: () => actualPromise(() => native.resetWrite()),
    waitTermination: () => termination,
    abort: () => native.abort(),
    onWriteFailure: callback => {
      if (typeof callback !== "function" || observer !== undefined) throw new Error("busy");
      const registration = { callback }; observer = registration;
      if (failure != null) queueMicrotask(() => {
        if (observer === registration) callback(failure);
      });
      return () => { if (observer === registration) observer = undefined; };
    },
  });
}
function session(native) {
  let preparationCompleted = false;
  const request = native.kind === "webtransport" ? Object.freeze(native.request()) : undefined;
  const termination = actualPromise(() => native.waitTermination());
  void termination.catch(() => {});
  return Object.freeze({
    kind: native.kind, wireVersion: native.wireVersion, path: native.path,
    ...(request === undefined ? {} : { request: () => request }),
    inboundBidirectionalStreamCapacity: native.inboundBidirectionalStreamCapacity,
    ...(typeof native.completePreparation !== "function" ? {} : {
      completePreparation: () => {
        if (preparationCompleted) return;
        // End the original native owner once. A failed completion does not
        // manufacture success or replace its original accounting state.
        native.completePreparation(); preparationCompleted = true;
      },
    }),
    tls: () => {
      const tls = native.tls();
      return Object.freeze({ version: tls.version, alpn: tls.alpn, earlyDataAccepted: tls.earlyDataAccepted,
        dedicatedConnection: tls.dedicatedConnection, peerLeafDER: tls.peerLeafDER, certificateVerified: tls.certificateVerified });
    },
    exportKeyingMaterial: (length, label, context) => native.exportKeyingMaterial(length, label, context),
    maxDatagramBytes: () => native.maxDatagramBytes(),
    receiveDatagram: maximum => operation(native.receiveDatagram(maximum), bytes => bytes),
    submitDatagram: bytes => submission(native.submitDatagram(bytes)),
    openStream: () => operation(native.openStream(), stream),
    acceptStream: () => operation(native.acceptStream(), stream),
    localAddress: () => Object.freeze(native.localAddress()),
    peerAddress: () => Object.freeze(native.peerAddress()),
    close: () => actualPromise(() => native.close()),
    waitTermination: () => termination,
    abort: () => native.abort(),
  });
}
function listener(native) {
  let termination;
  return Object.freeze({
    address: () => Object.freeze(native.address()),
    accept: () => operation(native.accept(), session),
    stopAcceptingCurrent: () => native.stopAcceptingCurrent(),
    close: () => actualPromise(() => native.close()),
    waitTermination: () => termination ??= actualPromise(() => native.waitTermination()),
    abort: () => native.abort(),
  });
}
function currentBinding(native) {
  if (native === null || typeof native !== "object" || typeof native.contractVersion !== "function" || native.contractVersion() !== 4 ||
      typeof native.connectRawQuic !== "function" || typeof native.bindRawQuic !== "function") throw unavailable();
  return Object.freeze({
    contractVersion: () => 4,
    sqliteExtensionPath: () => {
      if (typeof native.sqliteAdmissionVersion !== "function" || native.sqliteAdmissionVersion() !== 1) throw unavailable();
      return require.resolve(platformPackage);
    },
    // The factory and opaque candidate handles stay native originals. Facade
    // observations never reconstruct an owner or reset failed attempt usage.
    ...(typeof native.createPreparationBudget !== "function" ? {} : {
      createPreparationBudget: () => native.createPreparationBudget(),
    }),
    connectRawQuic: options => operation(native.connectRawQuic(options), session),
    bindRawQuic: options => actualPromise(() => native.bindRawQuic(options)).then(listener),
    ...(typeof native.connectWebTransport !== "function" || typeof native.bindWebTransport !== "function" ? {} : {
      connectWebTransport: options => operation(native.connectWebTransport(options), session),
      bindWebTransport: options => actualPromise(() => native.bindWebTransport(options)).then(listener),
    }),
  });
}
