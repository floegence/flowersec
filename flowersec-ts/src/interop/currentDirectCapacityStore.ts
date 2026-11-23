import { constants } from 'node:fs';
import { open, link, unlink } from 'node:fs/promises';
import { randomUUID, createHash } from 'node:crypto';
import { isAbsolute, join } from 'node:path';
import { parseArtifact } from '../node/index.js';

export async function privateBytes(path: string, max: number, privateOnly = true) {
  if (!isAbsolute(path)) throw new Error('absolute deployment input required');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || (privateOnly ? stat.mode & 0o077 : stat.mode & 0o022) || stat.size < 1 || stat.size > max) throw new Error('invalid deployment file');
    const result = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < result.length) {
      const { bytesRead } = await file.read(result, offset, result.length - offset);
      if (!bytesRead) throw new Error('short deployment file');
      offset += bytesRead;
    }
    if ((await file.read(Buffer.alloc(1))).bytesRead) throw new Error('deployment file changed');
    return result;
  } finally { await file.close(); }
}

export function positionArtifact(raw: Buffer, id: string, endpoint: string) {
  const handle = parseArtifact(raw), value = JSON.parse(raw.toString('utf8'));
  const candidate = value.path?.candidates?.[0];
  if (value.v !== 5 || value.profile !== 'flowersec/5' || value.session?.channel_id !== id || value.path.kind !== 'direct' ||
    value.path.candidates.length !== 1 || candidate?.carrier !== 'websocket' || candidate.url !== endpoint ||
    candidate.tls?.mode !== 'ca' || typeof value.path.routing_token !== 'string') throw new Error('incorrect published position');
  return { handle, key: createHash('sha256').update(value.path.routing_token).digest('base64url') };
}

export async function durableMark(directory: string, kind: 'admitted'|'spent'|'released', key: string) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(key)) throw new Error('invalid grant key');
  const staged = join(directory, '.stage-' + randomUUID());
  const file = await open(staged, 'wx', 0o600);
  try {
    try { await file.writeFile('flowersec/5\n'); await file.sync(); } finally { await file.close(); }
    await link(staged, join(directory, kind + '-' + key));
  } finally { await unlink(staged); }
  const parent = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
  try { await parent.sync(); } finally { await parent.close(); }
}
