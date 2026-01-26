# Custom Yamux Streams (Meta + Bytes Pattern)

This document describes the recommended way to build **custom yamux streams** on top of Flowersec.
It is intended for advanced integrations that go beyond the built-in RPC stream.

See also:

- Stable API surface: `docs/API_SURFACE.md`
- Protocol framing (wire format): `docs/PROTOCOL.md`

## When to use a custom stream

Use a custom stream when you need a protocol that is not RPC-shaped, for example:

- file preview / download (request metadata + raw bytes)
- HTTP proxying (request/response headers + body stream)

The recommended base pattern is:

1) **JSON meta frame** (length-prefixed)
2) **raw bytes** (exactly `content_len` bytes)

This keeps metadata structured and keeps large payloads efficient (no base64).

## Recommended framing helpers (stable)

TypeScript:

- `@floegence/flowersec-core/framing` (length-prefixed JSON framing)
- `@floegence/flowersec-core/streamio` (ByteReader + abort-aware helpers)

Go:

- `github.com/floegence/flowersec/flowersec-go/framing/jsonframe` (length-prefixed JSON framing)

## Size limits and safety

Do not read framed JSON without a size guard on untrusted inputs:

- TS: use `DEFAULT_MAX_JSON_FRAME_BYTES`
- Go: use `jsonframe.DefaultMaxJSONFrameBytes`

For the raw bytes payload, the protocol MUST include an explicit length and the implementation MUST enforce a max.
Do not accept unlimited payload sizes.

## Cancellation semantics

TypeScript:

- Pass an `AbortSignal` to `client.openStream(kind, { signal })` to cancel stream opening/hello.
- Use `createByteReader(stream, { signal })` and pass the same `signal` to read loops (e.g. `readNBytes`) so a user cancel stops work promptly.

Go:

- Use `context.Context` in your handler; stop work early if `ctx.Done()` is closed.
- A client-side reset/close will also surface as read/write errors on the stream.

## Example: TypeScript client (meta + bytes)

```ts
import type { Client } from "@floegence/flowersec-core";
import { DEFAULT_MAX_JSON_FRAME_BYTES, readJsonFrame, writeJsonFrame } from "@floegence/flowersec-core/framing";
import { createByteReader, readNBytes } from "@floegence/flowersec-core/streamio";

type ReadFileRequest = {
  path: string;
  offset?: number;
  max_bytes: number;
};

type ReadFileResponse = {
  content_len: number;
  content_type?: string;
};

export async function readFileOverStream(client: Client, req: ReadFileRequest, opts: { signal?: AbortSignal } = {}) {
  const stream = await client.openStream("fs/read_file", { signal: opts.signal });
  const reader = createByteReader(stream, { signal: opts.signal });

  await writeJsonFrame(stream, req);
  const meta = (await readJsonFrame(reader, DEFAULT_MAX_JSON_FRAME_BYTES)) as ReadFileResponse;

  // Note: readNBytes allocates a single buffer of size content_len. For large downloads,
  // prefer a streaming loop using stream.read() and writing to your sink incrementally.
  const bytes = await readNBytes(reader, meta.content_len, { signal: opts.signal, chunkSize: 64 * 1024 });

  await stream.close();
  return { meta, bytes };
}
```

## Example: Go server handler (meta + bytes)

This shows how to register a custom stream kind handler using the recommended server runtime `endpoint/serve`.

```go
package main

import (
	"context"
	"encoding/json"
	"io"

	"github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
)

type ReadFileRequest struct {
	Path     string `json:"path"`
	Offset   int64  `json:"offset"`
	MaxBytes int64  `json:"max_bytes"`
}

type ReadFileResponse struct {
	ContentLen  int64  `json:"content_len"`
	ContentType string `json:"content_type,omitempty"`
}

const maxAllowedBytes = 8 << 20

func registerHandlers(srv *serve.Server) {
	srv.Handle("fs/read_file", func(ctx context.Context, stream io.ReadWriteCloser) {
		b, err := jsonframe.ReadJSONFrame(stream, jsonframe.DefaultMaxJSONFrameBytes)
		if err != nil {
			return
		}
		var req ReadFileRequest
		if err := json.Unmarshal(b, &req); err != nil {
			return
		}
		if req.MaxBytes <= 0 || req.MaxBytes > maxAllowedBytes {
			return
		}

		// Application logic: resolve + open the file and decide how many bytes to send.
		// This example omits actual file IO; always enforce an upper bound before streaming.
		n := req.MaxBytes

		_ = jsonframe.WriteJSONFrame(stream, ReadFileResponse{ContentLen: n, ContentType: "application/octet-stream"})

		// Stream raw bytes in chunks; stop early on ctx cancel or stream errors.
		buf := make([]byte, 64*1024)
		var sent int64
		for sent < n {
			select {
			case <-ctx.Done():
				return
			default:
			}
			want := int64(len(buf))
			if n-sent < want {
				want = n - sent
			}
			if _, err := stream.Write(buf[:want]); err != nil {
				return
			}
			sent += want
		}
	})
}
```

