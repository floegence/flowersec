import { ed25519 } from "@noble/curves/ed25519";

import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";

export const TOKEN_PREFIX = "FST2";

export type TokenPayload = Readonly<{
  kid: string;
  aud: string;
  iss?: string;
  channel_id: string;
  role: 1 | 2;
  token_id: string;
  init_exp: number;
  idle_timeout_seconds: number;
  iat: number;
  exp: number;
}>;

export type ParsedToken = Readonly<{
  payload: TokenPayload;
  signed: Uint8Array;
  signature: Uint8Array;
}>;

export type TokenVerifyOptions = Readonly<{
  nowUnixS?: number;
  audience?: string;
  issuer?: string;
  clockSkewMs?: number;
}>;

export type TokenKeyLookup = ReadonlyMap<string, Uint8Array> | ((kid: string) => Uint8Array | undefined);

export class TokenError extends Error {
  constructor(readonly code: string, message = code) {
    super(message);
    this.name = "TokenError";
  }
}

export function signToken(signingSeed: Uint8Array, payload: TokenPayload): string {
  if (signingSeed.length !== 32) throw new TokenError("invalid_signing_key");
  const normalized = normalizePayload(payload, true);
  const payloadJSON = new TextEncoder().encode(JSON.stringify(normalized));
  const signedText = `${TOKEN_PREFIX}.${base64urlEncode(payloadJSON)}`;
  const signature = ed25519.sign(new TextEncoder().encode(signedText), signingSeed);
  return `${signedText}.${base64urlEncode(signature)}`;
}

export function parseToken(token: string): ParsedToken {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) throw new TokenError("invalid_format");
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1]!))) as TokenPayload;
    return {
      payload,
      signed: new TextEncoder().encode(`${TOKEN_PREFIX}.${parts[1]}`),
      signature: base64urlDecode(parts[2]!),
    };
  } catch (error) {
    if (error instanceof SyntaxError) throw new TokenError("invalid_json");
    throw new TokenError("invalid_base64url");
  }
}

export function verifyToken(token: string, keys: TokenKeyLookup, options: TokenVerifyOptions = {}): TokenPayload {
  const parsed = parseToken(token);
  const payload = normalizePayload(parsed.payload, false);
  const publicKey = typeof keys === "function" ? keys(payload.kid) : keys.get(payload.kid);
  if (publicKey == null) throw new TokenError("unknown_kid");
  if (publicKey.length !== 32 || parsed.signature.length !== 64 || !ed25519.verify(parsed.signature, parsed.signed, publicKey)) {
    throw new TokenError("invalid_signature");
  }
  if (options.audience !== undefined && !constantTimeTextEqual(payload.aud, options.audience)) throw new TokenError("invalid_audience");
  if (options.issuer !== undefined && !constantTimeTextEqual(payload.iss ?? "", options.issuer)) throw new TokenError("invalid_issuer");

  const skewMs = options.clockSkewMs ?? 0;
  if (!Number.isFinite(skewMs) || skewMs < 0) throw new TokenError("invalid_clock_skew");
  const skewSeconds = Math.ceil(skewMs / 1000);
  const now = options.nowUnixS ?? Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(now)) throw new TokenError("invalid_time");
  if (payload.iat > now + skewSeconds) throw new TokenError("iat_in_future");
  if (payload.init_exp < now - skewSeconds) throw new TokenError("init_expired");
  if (payload.exp < now - skewSeconds) throw new TokenError("expired");
  return payload;
}

export function equalSignedTokenPart(left: string, right: string): boolean {
  const leftPart = left.lastIndexOf(".");
  const rightPart = right.lastIndexOf(".");
  if (leftPart <= 0 || rightPart <= 0) return false;
  return constantTimeTextEqual(left.slice(0, leftPart), right.slice(0, rightPart));
}

function normalizePayload(input: TokenPayload, signing: boolean): TokenPayload {
  const kid = String(input?.kid ?? "").trim();
  const aud = String(input?.aud ?? "").trim();
  const iss = String(input?.iss ?? "").trim();
  const channelId = String(input?.channel_id ?? "").trim();
  const tokenId = String(input?.token_id ?? "").trim();
  if (kid === "" || tokenId === "" || (signing && aud === "")) throw new TokenError("invalid_format");
  if (channelId === "" || new TextEncoder().encode(channelId).length > 256) throw new TokenError("invalid_format");
  if (input.role !== 1 && input.role !== 2) throw new TokenError("invalid_format");
  for (const [name, value] of [["init_exp", input.init_exp], ["iat", input.iat], ["exp", input.exp], ["idle_timeout_seconds", input.idle_timeout_seconds]] as const) {
    if (!Number.isSafeInteger(value)) throw new TokenError("invalid_format", `invalid ${name}`);
  }
  if (input.idle_timeout_seconds <= 0) throw new TokenError("invalid_idle_timeout");
  if (signing && (input.init_exp <= 0 || input.iat <= 0 || input.exp <= 0)) throw new TokenError("invalid_format");
  if (input.exp > input.init_exp) throw new TokenError("exp_after_init");
  if (input.iat > input.exp) throw new TokenError("invalid_format");
  return {
    kid,
    aud,
    ...(iss === "" ? {} : { iss }),
    channel_id: channelId,
    role: input.role,
    token_id: tokenId,
    init_exp: input.init_exp,
    idle_timeout_seconds: input.idle_timeout_seconds,
    iat: input.iat,
    exp: input.exp,
  };
}

function constantTimeTextEqual(left: string, right: string): boolean {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index++) diff |= (a[index] ?? 0) ^ (b[index] ?? 0);
  return diff === 0;
}
