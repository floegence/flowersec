import type { ChannelInitGrant, Suite } from "../gen/flowersec/controlplane/v1.gen.js";
import { Role } from "../gen/flowersec/controlplane/v1.gen.js";
import { base64urlEncode } from "../utils/base64url.js";
import type { IssuerKeyset } from "./issuer.js";

export const CHANNEL_INIT_WINDOW_SECONDS = 120;
export const DEFAULT_IDLE_TIMEOUT_SECONDS = 60;
export const DEFAULT_TOKEN_EXP_SECONDS = 60;

export type ChannelInitParams = Readonly<{
  tunnelUrl: string;
  tunnelAudience: string;
  issuerId: string;
  tokenExpSeconds?: number;
  idleTimeoutSeconds?: number;
  clockSkewMs?: number;
  allowedSuites?: readonly Suite[];
  defaultSuite?: Suite;
}>;

export class ChannelInitService {
  constructor(
    private readonly issuer: IssuerKeyset,
    private readonly params: ChannelInitParams,
    private readonly nowUnixS: () => number = () => Math.floor(Date.now() / 1000),
  ) {}

  issue(channelIdInput: string): Readonly<{ client: ChannelInitGrant; server: ChannelInitGrant }> {
    const params = normalizeParams(this.params);
    const channelId = normalizeChannelId(channelIdInput);
    const psk = crypto.getRandomValues(new Uint8Array(32));
    let pskB64u: string;
    try {
      pskB64u = base64urlEncode(psk);
    } finally {
      psk.fill(0);
    }
    const now = normalizeNow(this.nowUnixS());
    const initExp = now + CHANNEL_INIT_WINDOW_SECONDS;
    const grant = (role: Role, token: string): ChannelInitGrant => ({
      tunnel_url: params.tunnelUrl,
      channel_id: channelId,
      channel_init_expire_at_unix_s: initExp,
      idle_timeout_seconds: params.idleTimeoutSeconds,
      role,
      token,
      e2ee_psk_b64u: pskB64u,
      allowed_suites: [...params.allowedSuites],
      default_suite: params.defaultSuite,
    });
    return {
      client: grant(Role.Role_client, this.signRoleToken(channelId, Role.Role_client, initExp, params.idleTimeoutSeconds, params.tokenExpSeconds, now, params)),
      server: grant(Role.Role_server, this.signRoleToken(channelId, Role.Role_server, initExp, params.idleTimeoutSeconds, params.tokenExpSeconds, now, params)),
    };
  }

  reissue(grant: ChannelInitGrant): ChannelInitGrant {
    const params = normalizeParams(this.params);
    if (grant.idle_timeout_seconds <= 0 || (grant.role !== Role.Role_client && grant.role !== Role.Role_server)) throw new Error("invalid grant");
    const now = normalizeNow(this.nowUnixS());
    const skewSeconds = Math.ceil(params.clockSkewMs / 1000);
    if (now > grant.channel_init_expire_at_unix_s + skewSeconds) throw new Error("channel init expired");
    return {
      ...grant,
      token: this.signRoleToken(
        normalizeChannelId(grant.channel_id),
        grant.role,
        grant.channel_init_expire_at_unix_s,
        grant.idle_timeout_seconds,
        params.tokenExpSeconds,
        now,
        params,
      ),
    };
  }

  private signRoleToken(
    channelId: string,
    role: Role,
    initExp: number,
    idleTimeoutSeconds: number,
    tokenExpSeconds: number,
    now: number,
    params: ReturnType<typeof normalizeParams>,
  ): string {
    const iat = Math.min(now, initExp);
    const exp = Math.min(initExp, iat + tokenExpSeconds);
    const tokenId = crypto.getRandomValues(new Uint8Array(24));
    try {
      return this.issuer.sign({
        aud: params.tunnelAudience,
        iss: params.issuerId,
        channel_id: channelId,
        role: role as 1 | 2,
        token_id: base64urlEncode(tokenId),
        init_exp: initExp,
        idle_timeout_seconds: idleTimeoutSeconds,
        iat,
        exp,
      });
    } finally {
      tokenId.fill(0);
    }
  }
}

function normalizeParams(params: ChannelInitParams) {
  const tunnelUrl = params.tunnelUrl.trim();
  const tunnelAudience = params.tunnelAudience.trim();
  const issuerId = params.issuerId.trim();
  if (tunnelUrl === "") throw new Error("missing tunnel URL");
  if (tunnelAudience === "") throw new Error("missing tunnel audience");
  if (issuerId === "") throw new Error("missing issuer ID");
  const tokenExpSeconds = normalizeNonNegative("tokenExpSeconds", params.tokenExpSeconds ?? 0) || DEFAULT_TOKEN_EXP_SECONDS;
  const idleTimeoutSeconds = normalizeNonNegative("idleTimeoutSeconds", params.idleTimeoutSeconds ?? 0) || DEFAULT_IDLE_TIMEOUT_SECONDS;
  const clockSkewMs = normalizeNonNegative("clockSkewMs", params.clockSkewMs ?? 0);
  const allowedSuites = [...new Set(params.allowedSuites?.length ? params.allowedSuites : [1 as Suite])];
  for (const suite of allowedSuites) if (suite !== 1 && suite !== 2) throw new Error("unsupported suite");
  const defaultSuite = params.defaultSuite ?? allowedSuites[0]!;
  if (!allowedSuites.includes(defaultSuite)) throw new Error("default suite not allowed");
  return { tunnelUrl, tunnelAudience, issuerId, tokenExpSeconds, idleTimeoutSeconds, clockSkewMs, allowedSuites, defaultSuite };
}

function normalizeChannelId(input: string): string {
  const value = input.trim();
  if (value === "" || new TextEncoder().encode(value).length > 256) throw new Error("invalid channel ID");
  return value;
}

function normalizeNonNegative(name: string, value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer`);
  return value;
}

function normalizeNow(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error("invalid clock");
  return value;
}
