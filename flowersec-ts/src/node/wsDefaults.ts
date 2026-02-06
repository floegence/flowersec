const defaultMaxHandshakePayload = 8 * 1024;
const defaultMaxRecordBytes = 1 << 20;
const handshakeFrameOverheadBytes = 4 + 1 + 1 + 4;
const wsMaxPayloadSlackBytes = 64;

export function defaultWsMaxPayload(opts: Readonly<{ maxHandshakePayload?: number; maxRecordBytes?: number }>): number {
  const maxHandshakePayload = opts.maxHandshakePayload ?? 0;
  const maxRecordBytes = opts.maxRecordBytes ?? 0;

  const hp =
    Number.isSafeInteger(maxHandshakePayload) && maxHandshakePayload > 0 ? maxHandshakePayload : defaultMaxHandshakePayload;
  const rb = Number.isSafeInteger(maxRecordBytes) && maxRecordBytes > 0 ? maxRecordBytes : defaultMaxRecordBytes;

  const handshakeMax = Math.min(Number.MAX_SAFE_INTEGER, hp + handshakeFrameOverheadBytes);
  const max = Math.max(rb, handshakeMax);
  return Math.min(Number.MAX_SAFE_INTEGER, max + wsMaxPayloadSlackBytes);
}

