import type { CryptoUsageLedger, CryptoKeyPositions } from "./cryptoUsage.js";
import { directionKeyCharge } from "./maintenancePositions.js";
import { receiveDirectionCharge, receiveDecoderCharge, receiveCursorCharge, type ReceiveDirectionConfig } from "./receiveDirection.js";
import type { NativeProtocolPosition } from "./nativePositions.js";
import { ResourceVector, type ResourceReference, type ResourceRoot, type ResourceAccount, type ProtectedResourceReservation } from "./resources.js";

export function streamTerminationCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([runtimeBytes + 1536n, 0n, 0n, 3n, 3n, 3n, 2n, 0n, 0n, 1n, 0n]);
}
export function streamOpenCharges(maxFrame: number, runtimeBytes: bigint, receive: ReceiveDirectionConfig, sendMaxFrame = maxFrame): readonly ResourceVector[] {
  const receiveCipher = { maxFrame, runtimeBytes }, sendCipher = { maxFrame: sendMaxFrame, runtimeBytes };
  return [directionKeyCharge(receiveCipher), directionKeyCharge(receiveCipher), directionKeyCharge(sendCipher), directionKeyCharge(sendCipher),
    streamTerminationCharge(runtimeBytes), receiveDirectionCharge(receive), receiveDecoderCharge(receive), receiveCursorCharge(receive),
    new ResourceVector([runtimeBytes + 1024n, 0n, 0n, 1n, 1n, 1n, 1n, 0n, 0n, 1n, 0n])];
}
/** Resource ownership only. The Session still allocates and authenticates the
 * original logical scope, keys and native association at its OPEN gate. */
export class StreamOpenPreparation {
  readonly #references: ResourceReference[];
  #native: NativeProtocolPosition | undefined;
  #sendKeys: CryptoKeyPositions | undefined;
  #receiveKeys: CryptoKeyPositions | undefined;
  #account: ResourceAccount | undefined;
  readonly wait: ProtectedResourceReservation;
  #closed = false;
  constructor(root: ResourceRoot, charges: readonly ResourceVector[], references: readonly ResourceReference[], account: ResourceAccount, native?: NativeProtocolPosition) {
    if (charges.length !== 9 || references.length !== 9) throw new Error("configuration_capacity");
    this.#references = []; this.#account = account; this.#native = native;
    this.wait = root.protect(references[8]!, charges[8]!);
    try { for (let index = 0; index < 8; index++) this.#references.push(references[index]!.take(charges[index]!)); }
    catch (error) { this.close(); throw error; }
  }
  prepareSendKeys(ledger: CryptoUsageLedger): void {
    if (this.#closed || this.#sendKeys !== undefined || this.#references.length !== 8) throw new Error("owner_unavailable");
    this.#sendKeys = ledger.prepareKeyPositions(ledger.sendDirection, this.#references[2]!);
  }
  prepareReceiveKeys(ledger: CryptoUsageLedger): void {
    if (this.#closed || this.#receiveKeys !== undefined || this.#references.length !== 8) throw new Error("owner_unavailable");
    this.#receiveKeys = ledger.prepareKeyPositions(ledger.sendDirection === 0 ? 1 : 0, this.#references[0]!);
  }
  take(reference: ResourceReference): Readonly<{ references: readonly ResourceReference[]; account: ResourceAccount; native: NativeProtocolPosition | undefined; sendKeys: CryptoKeyPositions | undefined; receiveKeys: CryptoKeyPositions | undefined }> {
    if (this.#closed || this.#account === undefined || this.#references.length !== 8 || !this.#references.every(part => part.sameEnvironment(reference))) throw new Error("owner_unavailable");
    const result = { references: this.#references.splice(0), account: this.#account, native: this.#native, sendKeys: this.#sendKeys, receiveKeys: this.#receiveKeys };
    this.#account = undefined; this.#native = undefined; this.#sendKeys = undefined; this.#receiveKeys = undefined; return result;
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#receiveKeys?.close(); this.#receiveKeys = undefined; this.#sendKeys?.close(); this.#sendKeys = undefined;
    for (const reference of this.#references) reference.release(); this.#references.length = 0;
    for (const reference of this.#native?.references ?? []) reference.release(); this.#native = undefined;
    this.#account?.close(); this.#account = undefined; this.wait.closeAfterUse();
  }
}
