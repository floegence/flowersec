// Test-only Noise primitive adapter.  This deliberately accepts an arbitrary
// prologue so the pinned primitive corpus can test the underlying Snow/WASM
// implementation in isolation.  Production v4 code must use NoiseHandshake,
// whose constructor builds the fixed FSB4/FSA4-bound prologue.
import { transportV4NoiseWasmBase64 } from "../runtime/noiseWasmBinary.js";
import type { NoiseProfile, NoiseRole } from "../runtime/noiseHandshake.js";

type Exports = {
  readonly memory: WebAssembly.Memory;
  readonly fs_noise_abi: () => number;
  readonly fs_noise_io: () => number;
  readonly fs_noise_start: () => number;
  readonly fs_noise_write: () => number;
  readonly fs_noise_read: (size: number) => number;
  readonly fs_noise_finish: () => number;
  readonly fs_noise_close: () => void;
};
const maximum = 1_048_576;
let module: WebAssembly.Module | undefined;
function decode(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const output = new Uint8Array(Math.floor(value.length * 3 / 4)); let accumulator = 0, bits = 0, at = 0;
  for (const char of value) { if (char === "=") break; const digit = alphabet.indexOf(char); if (digit < 0) throw new Error("noise_fixture"); accumulator = ((accumulator << 6) | digit) & 0xffffff; bits += 6; if (bits >= 8) { bits -= 8; output[at++] = (accumulator >> bits) & 0xff; } }
  return at === output.length ? output : output.subarray(0, at);
}
function instance(): Exports {
  module ??= new WebAssembly.Module(decode(transportV4NoiseWasmBase64) as unknown as BufferSource);
  const value = new WebAssembly.Instance(module).exports as unknown as Exports;
  if (value.fs_noise_abi() !== 1) throw new Error("noise_fixture");
  return value;
}
function profileCode(profile: NoiseProfile): number {
  if (profile === "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1") return 0;
  if (profile === "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1") return 1;
  throw new Error("noise_fixture");
}
function roleCode(role: NoiseRole): number { if (role === "client") return 0; if (role === "server") return 1; throw new Error("noise_fixture"); }
function copy(value: Uint8Array, expected: number): Uint8Array { if (value.length !== expected) throw new Error("noise_fixture"); return Uint8Array.from(value); }

export interface PrimitiveNoiseConfig {
  readonly profile: NoiseProfile; readonly role: NoiseRole;
  readonly localStaticPrivate: Uint8Array; readonly localStaticPublic: Uint8Array;
  readonly peerStaticPublic: Uint8Array; readonly psk: Uint8Array;
  readonly ephemeralPrivate: Uint8Array; readonly prologue: Uint8Array;
  readonly contextDigest: Uint8Array;
}

export class PrimitiveNoiseHandshake {
  readonly #profile: NoiseProfile; #exports: Exports | undefined; #closed = false; #written = false; #read = false;
  constructor(config: PrimitiveNoiseConfig) {
    const publicBytes = config.profile === "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1" ? 32 : 65;
    const localPrivate = copy(config.localStaticPrivate, 32), localPublic = copy(config.localStaticPublic, publicBytes), peerPublic = copy(config.peerStaticPublic, publicBytes), psk = copy(config.psk, 32), ephemeral = copy(config.ephemeralPrivate, 32), context = copy(config.contextDigest, 32), prologue = copy(config.prologue, config.prologue.length);
    if (prologue.length === 0 || prologue.length > maximum - 266) throw new Error("noise_fixture");
    const e = instance();
    try {
      const io = e.fs_noise_io(), view = new Uint8Array(e.memory.buffer, io, maximum); view.fill(0);
      view[0] = profileCode(config.profile); view[1] = roleCode(config.role); view.set(localPrivate, 4); view.set(localPublic, 36); view.set(peerPublic, 101); view.set(psk, 166); view.set(ephemeral, 198);
      new DataView(view.buffer, view.byteOffset, view.byteLength).setUint32(230, prologue.length); view.set(context, 234); view.set(prologue, 266);
      if (e.fs_noise_start() < 0) throw new Error("noise_fixture"); this.#exports = e; this.#profile = config.profile;
    } catch (error) { e.fs_noise_close(); throw error; } finally { localPrivate.fill(0); psk.fill(0); ephemeral.fill(0); context.fill(0); prologue.fill(0); }
  }
  writeMessage(): Uint8Array { const e = this.#exports; if (!e || this.#closed || this.#written) throw new Error("noise_fixture"); const size = e.fs_noise_write(); const expected = this.#profile.includes("x25519") ? 48 : 81; if (size !== expected) { this.close(); throw new Error("noise_fixture"); } this.#written = true; return Uint8Array.from(new Uint8Array(e.memory.buffer, e.fs_noise_io(), size)); }
  readMessage(message: Uint8Array): void { const e = this.#exports; if (!e || this.#closed || this.#read) throw new Error("noise_fixture"); const expected = this.#profile.includes("x25519") ? 48 : 81; if (message.length !== expected) { this.close(); throw new Error("noise_fixture"); } const io = e.fs_noise_io(); new Uint8Array(e.memory.buffer, io, message.length).set(message); if (e.fs_noise_read(message.length) < 0) { this.close(); throw new Error("noise_fixture"); } this.#read = true; }
  finish(): Readonly<{ initialRoot: Uint8Array; handshakeHash: Uint8Array }> {
    const e = this.#exports;
    if (!e || this.#closed || !this.#read || !this.#written || e.fs_noise_finish() !== 64) throw new Error("noise_fixture");
    const output = Uint8Array.from(new Uint8Array(e.memory.buffer, e.fs_noise_io(), 64));
    try { return { initialRoot: output.slice(0, 32), handshakeHash: output.slice(32) }; }
    finally { output.fill(0); this.close(); }
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#exports?.fs_noise_close(); this.#exports = undefined; }
}
