import { createStreamMetadata } from '@floegence/flowersec-core/node';
import { ParityEndpoint } from './parity.mjs';

/** @typedef {import('@floegence/flowersec-core/node').JsonValue} JsonValue */
/** @typedef {import('@floegence/flowersec-core/node').ByteStream} ByteStream */
/** @typedef {import('@floegence/flowersec-core/node').Session} Session */
/** @typedef {Parameters<Parameters<import('@floegence/flowersec-core/node').RPCHandlers['handleRPC']>[1]>[1]} Request */

const large = 1 << 20;
const kind = 'public-release-roundtrip';
export const capacityFrameBytes = large + 256;

/** @param {JsonValue} payload @returns {string | undefined} */
function echoValue(payload) {
  if (payload === null || typeof payload !== 'object' || !('payload' in payload) || Object.keys(payload).length !== 1) return;
  const value = payload.payload;
  return typeof value === 'string' ? value : undefined;
}

export class CapacityParityEndpoint extends ParityEndpoint {
  /** @param {JsonValue} payload @param {Request} request */
  async echo(payload, request) {
    const value = echoValue(payload);
    if (value === undefined) return super.echo(payload, request);
    request.signal?.throwIfAborted();
    if (!this.allows(7001)) return { error: { code: 403, message: 'capacity echo unavailable' } };
    if ((value.length !== 256 && value.length !== large) || /[^Z]/u.test(value)) return { error: { code: 400, message: 'invalid capacity echo' } };
    return { payload };
  }
}

/** @param {ByteStream} stream @param {number} size @param {number} octet @param {AbortSignal} signal */
async function writeAndFinish(stream, size, octet, signal) {
  const bytes = Buffer.alloc(size, octet);
  let offset = 0;
  while (offset < size) {
    const used = await stream.write(bytes.subarray(offset), { signal });
    if (!Number.isSafeInteger(used) || used < 1 || used > size - offset) throw new Error('invalid stream write count');
    offset += used;
  }
  signal.throwIfAborted();
  await stream.closeWrite();
}

/** @param {ByteStream} stream @param {number} size @param {number} octet @param {AbortSignal} signal */
async function readAndVerify(stream, size, octet, signal) {
  let received = 0;
  for (;;) {
    const part = await stream.read({ signal });
    if (part === null) break;
    if (!part.length || part.length > size - received || part.some(byte => byte !== octet)) throw new Error('capacity stream payload differs');
    received += part.length;
  }
  if (received !== size) throw new Error('incomplete capacity stream');
}

/** @param {ByteStream} stream @param {() => Promise<void>} transfer @param {AbortController} cancellation */
async function ownStream(stream, transfer, cancellation) {
  try {
    await transfer();
  } catch (error) {
    cancellation.abort(error);
    try { await stream.reset(); } catch (cleanupError) { throw new AggregateError([error, cleanupError]); }
    throw error;
  }
}

/** @param {Session} client @param {Session} server @param {'echo'|'raw'} operation @param {number} size @param {AbortSignal} deadline */
export async function runCapacityBusiness(client, server, operation, size, deadline) {
  if (size !== 256 && size !== large) throw new Error('invalid capacity payload size');
  deadline.throwIfAborted();
  if (operation === 'echo') {
    const sent = 'Z'.repeat(size);
    const result = await client.rpc.call(7001, { payload: sent }, payload => payload, { signal: deadline });
    if (!result.ok || echoValue(result.payload) !== sent) throw new Error('capacity RPC echo differs');
    deadline.throwIfAborted();
    return { operation, requestBytes: size, responseBytes: size, verified: true };
  }
  if (operation !== 'raw') throw new Error('invalid business operation');
  const cancellation = new AbortController();
  const signal = AbortSignal.any([deadline, cancellation.signal]);
  const receive = async () => {
    const incoming = await server.acceptStream({ signal });
    await ownStream(incoming.stream, async () => {
      if (incoming.kind !== kind || incoming.metadata.values.direction !== 'client-to-server') throw new Error('capacity stream OPEN differs');
      await readAndVerify(incoming.stream, size, 0x5a, signal);
      await writeAndFinish(incoming.stream, size, 0x37, signal);
    }, cancellation);
  };
  const send = async () => {
    const stream = await client.openStream(kind, { signal, metadata: createStreamMetadata({ direction: 'client-to-server' }) });
    await ownStream(stream, async () => {
      await writeAndFinish(stream, size, 0x5a, signal);
      await readAndVerify(stream, size, 0x37, signal);
    }, cancellation);
  };
  const results = await Promise.allSettled([receive, send].map(async side => {
    try { await side(); } catch (error) { cancellation.abort(error); throw error; }
  }));
  for (const result of results) if (result.status === 'rejected') throw result.reason;
  deadline.throwIfAborted();
  return { operation, requestBytes: size, responseBytes: size, verified: true };
}
