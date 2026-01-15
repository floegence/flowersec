// base64urlEncode encodes bytes without padding.
export function base64urlEncode(bytes: Uint8Array): string {
  let b64: string;
  if (typeof Buffer !== "undefined") {
    b64 = Buffer.from(bytes).toString("base64");
  } else {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
    b64 = btoa(binary);
  }
  return b64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

// base64urlDecode decodes base64url without padding.
export function base64urlDecode(s: string): Uint8Array {
  const normalized = s.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + "=".repeat(padLen);
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
